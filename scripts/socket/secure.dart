import 'dart:convert';
import 'dart:io';

import 'package:http/io_client.dart';

// sudo tcpdump -i any port 53

void main() async {
  final client = HttpClient()
    ..badCertificateCallback = (X509Certificate cert, String host, int port) {
      print("badCertificateCallback");
      print(cert);
      print(host);
      print(port);
      return false;
    }
    ..connectionFactory = (Uri uri, String? proxyHost, int? proxyPort) async {
      print("connectionFactory");
      print(uri);
      print(proxyHost);
      print(proxyPort);

      final host = 'example.com';
      final port = 443;

      final ipList = await mySecureDnsLookup(host);
      final rawSocket = await Socket.connect(ipList.first, port);
      final secureSocket = SecureSocket.secure(rawSocket, host: host);

      return Future.value(ConnectionTask.fromSocket(secureSocket, () {}));
    };

  final ioclient = IOClient(client);

  final url = 'https://example.com/';

  final request = await client.getUrl(Uri.parse(url));
  final response1 = await request.close();
  print(">>> HTTPClient");
  print('Response status: ${response1.statusCode}');
  print(response1.headers);
  print("");
  print(await utf8.decodeStream(response1));
  print("");

  final response2 = await ioclient.get(Uri.parse(url));
  print(">>> IOClient");
  print('Response status: ${response2.statusCode}');
  print(response2.headers);
  print("");
  print(response2.body);
  print("");

  ioclient.close();
}

Future<List<InternetAddress>> mySecureDnsLookup(String host) async {
  // ここに自前のDNSSECやDoHなどの処理を書く

  return [InternetAddress('23.192.228.84')];
}
