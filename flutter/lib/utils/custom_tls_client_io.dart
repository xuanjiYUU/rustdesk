import 'dart:io';

import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

Future<SecurityContext>? _securityContext;

Future<SecurityContext> _loadSecurityContext() async {
  final context = SecurityContext(withTrustedRoots: true);
  final certificate = await rootBundle.load('assets/self_hosted_ca.pem');
  context.setTrustedCertificatesBytes(certificate.buffer.asUint8List());
  return context;
}

Future<http.Client> createSelfHostedHttpClient() async {
  _securityContext ??= _loadSecurityContext();
  final context = await _securityContext!;
  return IOClient(HttpClient(context: context));
}
