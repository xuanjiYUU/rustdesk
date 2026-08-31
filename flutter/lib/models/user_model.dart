import 'dart:async';
import 'dart:convert';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/models/ab_model.dart';
import 'package:get/get.dart';

import '../common.dart';
import '../utils/http_service.dart' as http;
import 'model.dart';
import 'platform_model.dart';

bool refreshingUser = false;
const kSelfHostedDeviceAliasOption = 'self-hosted-device-alias';
const kSelfHostedDeviceSharedOption = 'self-hosted-device-shared';
const kSelfHostedDefaultConnectionPassword = 'Zdrive-2026';

class UserModel {
  final RxString userName = ''.obs;
  final RxString displayName = ''.obs;
  final RxString avatar = ''.obs;
  final RxBool isAdmin = false.obs;
  final RxString networkError = ''.obs;
  // True when networkError carries a server-reported error rather than a
  // connectivity failure; netWorkErrorWidget hides the network tip then.
  final RxBool networkErrorFromServer = false.obs;
  bool get isLogin => userName.isNotEmpty;
  String get displayNameOrUserName =>
      displayName.value.trim().isEmpty ? userName.value : displayName.value;
  String get accountLabelWithHandle {
    final username = userName.value.trim();
    if (username.isEmpty) {
      return '';
    }
    final preferred = displayName.value.trim();
    if (preferred.isEmpty || preferred == username) {
      return username;
    }
    return '$preferred (@$username)';
  }

  WeakReference<FFI> parent;

  UserModel(this.parent) {
    userName.listen((p0) {
      // When user name becomes empty, show login button
      // When user name becomes non-empty:
      //  For _updateLocalUserInfo, network error will be set later
      //  For login success, should clear network error
      networkError.value = '';
    });
  }

  static String currentDeviceAlias() {
    return bind
        .mainGetLocalOption(key: kSelfHostedDeviceAliasOption)
        .trim();
  }

  static bool isCurrentDeviceShared() =>
      bind.mainGetLocalOption(key: kSelfHostedDeviceSharedOption) == 'Y';

  static Future<void> setCurrentDeviceAlias(String alias) async {
    await bind.mainSetLocalOption(
        key: kSelfHostedDeviceAliasOption, value: alias.trim());
  }

  Future<void> setCurrentDeviceSharing({
    required String alias,
    required bool shared,
  }) async {
    if (!isLogin) {
      throw '请先登录账号';
    }
    await setCurrentDeviceAlias(alias);
    if (shared) {
      final passwordSet = await bind.mainSetPermanentPasswordWithResult(
          password: kSelfHostedDefaultConnectionPassword);
      if (!passwordSet) {
        throw '设置默认连接密码失败';
      }
      await bind.mainSetLocalOption(
          key: kSelfHostedDeviceSharedOption, value: 'Y');
      try {
        await syncCurrentDevice(throwOnError: true);
      } catch (_) {
        await bind.mainSetLocalOption(
            key: kSelfHostedDeviceSharedOption, value: 'N');
        rethrow;
      }
    } else {
      await _unshareCurrentDevice();
      await bind.mainSetLocalOption(
          key: kSelfHostedDeviceSharedOption, value: 'N');
    }
    await gFFI.abModel.pullAb(
        force: ForcePullAb.listAndCurrent, quiet: true);
  }

  Future<void> syncCurrentDevice({bool throwOnError = false}) async {
    final token = bind.mainGetLocalOption(key: 'access_token');
    if (token.isEmpty || !isCurrentDeviceShared() || isWeb) {
      return;
    }
    try {
      Map<String, dynamic> info = {};
      try {
        info = jsonDecode(bind.mainGetLoginDeviceInfo());
      } catch (error) {
        debugPrint('Failed to decode current device info: $error');
      }
      final url = await bind.mainGetApiServer();
      final response = await http.post(Uri.parse('$url/api/device/upsert'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $token',
          },
          body: jsonEncode({
            'id': await bind.mainGetMyId(),
            'alias': currentDeviceAlias(),
            'hostname': (info['name'] ?? '').toString(),
            'platform': (info['os'] ?? '').toString(),
            'username': userName.value,
            'password': kSelfHostedDefaultConnectionPassword,
          }));
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw RequestException(response.statusCode,
            decode_http_response(response));
      }
    } catch (error) {
      // Device synchronization must not invalidate an otherwise valid login.
      debugPrint('Failed to synchronize current device: $error');
      if (throwOnError) {
        rethrow;
      }
    }
  }

  Future<void> reconcileCurrentDeviceSharing() async {
    try {
      if (isCurrentDeviceShared()) {
        await syncCurrentDevice();
      } else {
        await _unshareCurrentDevice();
      }
    } catch (error) {
      // Sharing state must not invalidate an otherwise valid account session.
      debugPrint('Failed to reconcile current device sharing: $error');
    }
  }

  Future<void> _unshareCurrentDevice() async {
    final token = bind.mainGetLocalOption(key: 'access_token');
    if (token.isEmpty || isWeb) {
      return;
    }
    final url = await bind.mainGetApiServer();
    final id = await bind.mainGetMyId();
    final response = await http.delete(Uri.parse('$url/api/device/$id'),
        headers: {'Authorization': 'Bearer $token'});
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw RequestException(
          response.statusCode, decode_http_response(response));
    }
  }

  void refreshCurrentUser() async {
    if (bind.isDisableAccount()) return;
    networkError.value = '';
    networkErrorFromServer.value = false;
    final token = bind.mainGetLocalOption(key: 'access_token');
    if (token == '') {
      await updateOtherModels();
      return;
    }
    _updateLocalUserInfo();
    final url = await bind.mainGetApiServer();
    final body = {
      'id': await bind.mainGetMyId(),
      'uuid': await bind.mainGetUuid()
    };
    if (refreshingUser) return;
    try {
      refreshingUser = true;
      final http.Response response;
      try {
        response = await http.post(Uri.parse('$url/api/currentUser'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer $token'
            },
            body: json.encode(body));
      } catch (e) {
        networkError.value = e.toString();
        rethrow;
      }
      refreshingUser = false;
      final status = response.statusCode;
      if (status == 401 || status == 400) {
        reset(resetOther: status == 401);
        return;
      }
      final data = json.decode(decode_http_response(response));
      final error = data['error'];
      if (error != null) {
        // The only failure known to come from the server itself, so the
        // check-your-network tip does not apply. Flag before the message is
        // set in the catch below so rebuilds read a consistent pair.
        networkErrorFromServer.value = true;
        throw error;
      }

      final user = UserPayload.fromJson(data);
      _parseAndUpdateUser(user);
    } catch (e) {
      debugPrint('Failed to refreshCurrentUser: $e');
      // Surface failures in the address book / group tabs, which offer a
      // retry. Anything not flagged above -- transport errors, non-JSON or
      // unexpected-schema bodies (e.g. a filter's block page) -- keeps the
      // check-your-network tip.
      if (networkError.value.isEmpty) {
        networkError.value = e.toString();
      }
    } finally {
      refreshingUser = false;
      await updateOtherModels();
    }
  }

  static Map<String, dynamic>? getLocalUserInfo() {
    final userInfo = bind.mainGetLocalOption(key: 'user_info');
    if (userInfo == '') {
      return null;
    }
    try {
      return json.decode(userInfo);
    } catch (e) {
      debugPrint('Failed to get local user info "$userInfo": $e');
    }
    return null;
  }

  _updateLocalUserInfo() {
    final userInfo = getLocalUserInfo();
    if (userInfo != null) {
      userName.value = (userInfo['name'] ?? '').toString();
      displayName.value = (userInfo['display_name'] ?? '').toString();
      avatar.value = (userInfo['avatar'] ?? '').toString();
    }
  }

  Future<void> reset({bool resetOther = false}) async {
    await bind.mainSetLocalOption(key: 'access_token', value: '');
    await bind.mainSetLocalOption(key: 'user_info', value: '');
    if (resetOther) {
      await gFFI.abModel.reset();
      await gFFI.groupModel.reset();
    }
    userName.value = '';
    displayName.value = '';
    avatar.value = '';
  }

  _parseAndUpdateUser(UserPayload user) {
    userName.value = user.name;
    displayName.value = user.displayName;
    avatar.value = user.avatar;
    isAdmin.value = user.isAdmin;
    bind.mainSetLocalOption(key: 'user_info', value: jsonEncode(user));
    if (isWeb) {
      // ugly here, tmp solution
      bind.mainSetLocalOption(key: 'verifier', value: user.verifier ?? '');
    }
  }

  // update ab and group status
  static Future<void> updateOtherModels() async {
    await gFFI.userModel.reconcileCurrentDeviceSharing();
    await Future.wait([
      gFFI.abModel.pullAb(force: ForcePullAb.listAndCurrent, quiet: false),
      gFFI.groupModel.pull()
    ]);
  }

  Future<void> logOut({String? apiServer}) async {
    final tag = gFFI.dialogManager.showLoading(translate('Waiting'));
    try {
      final url = apiServer ?? await bind.mainGetApiServer();
      final authHeaders = getHttpHeaders();
      authHeaders['Content-Type'] = "application/json";
      await http
          .post(Uri.parse('$url/api/logout'),
              body: jsonEncode({
                'id': await bind.mainGetMyId(),
                'uuid': await bind.mainGetUuid(),
              }),
              headers: authHeaders)
          .timeout(Duration(seconds: 2));
    } catch (e) {
      debugPrint("request /api/logout failed: err=$e");
    } finally {
      await reset(resetOther: true);
      gFFI.dialogManager.dismissByTag(tag);
    }
  }

  /// throw [RequestException]
  Future<LoginResponse> login(LoginRequest loginRequest) async {
    final url = await bind.mainGetApiServer();
    final resp = await http.post(Uri.parse('$url/api/login'),
        body: jsonEncode(loginRequest.toJson()));

    final Map<String, dynamic> body;
    try {
      body = jsonDecode(decode_http_response(resp));
    } catch (e) {
      debugPrint("login: jsonDecode resp body failed: ${e.toString()}");
      if (resp.statusCode != 200) {
        BotToast.showText(
            contentColor: Colors.red, text: 'HTTP ${resp.statusCode}');
      }
      rethrow;
    }
    if (resp.statusCode != 200) {
      throw RequestException(resp.statusCode, body['error'] ?? '');
    }
    if (body['error'] != null) {
      throw RequestException(0, body['error']);
    }

    return getLoginResponseFromAuthBody(body);
  }

  Future<LoginResponse> register(RegisterRequest registerRequest) async {
    final url = await bind.mainGetApiServer();
    final resp = await http.post(Uri.parse('$url/api/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(registerRequest.toJson()));

    final Map<String, dynamic> body;
    try {
      body = jsonDecode(decode_http_response(resp));
    } catch (e) {
      if (resp.statusCode != 200) {
        BotToast.showText(
            contentColor: Colors.red, text: 'HTTP ${resp.statusCode}');
      }
      rethrow;
    }
    if (resp.statusCode != 200 || body['error'] != null) {
      throw RequestException(resp.statusCode, body['error'] ?? '');
    }
    return getLoginResponseFromAuthBody(body);
  }

  LoginResponse getLoginResponseFromAuthBody(Map<String, dynamic> body) {
    final LoginResponse loginResponse;
    try {
      loginResponse = LoginResponse.fromJson(body);
    } catch (e) {
      debugPrint("login: jsonDecode LoginResponse failed: ${e.toString()}");
      rethrow;
    }

    final isLogInDone = loginResponse.type == HttpType.kAuthResTypeToken &&
        loginResponse.access_token != null;
    if (isLogInDone && loginResponse.user != null) {
      _parseAndUpdateUser(loginResponse.user!);
    }

    return loginResponse;
  }

  /// Throws on network failures, non-success responses, and invalid response
  /// data. Returns an empty list when no API server is configured or a
  /// successful response contains no third-party login options.
  static Future<List<dynamic>> queryOidcLoginOptions() async {
    final url = await bind.mainGetApiServer();
    if (url.trim().isEmpty) return [];
    final resp = await http.get(Uri.parse('$url/api/login-options'));
    const successStatusCodeStart = 200;
    const successStatusCodeEnd = 300;
    if (resp.statusCode < successStatusCodeStart ||
        resp.statusCode >= successStatusCodeEnd) {
      throw RequestException(
          resp.statusCode, resp.reasonPhrase ?? 'Request failed');
    }
    final List<String> ops = [];
    for (final item in jsonDecode(resp.body)) {
      ops.add(item as String);
    }
    for (final item in ops) {
      if (item.startsWith('common-oidc/')) {
        return jsonDecode(item.substring('common-oidc/'.length));
      }
    }
    return ops
        .where((item) => item.startsWith('oidc/'))
        .map((item) => {'name': item.substring('oidc/'.length)})
        .toList();
  }
}
