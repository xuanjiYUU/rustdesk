import 'package:http/http.dart' as http;

Future<http.Client> createSelfHostedHttpClient() async => http.Client();
