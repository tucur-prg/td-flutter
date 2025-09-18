import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

// sudo tcpdump -i any port 53

void main() async {
  final context = SecurityContext.defaultContext;
  context.minimumTlsProtocolVersion = TlsProtocolVersion.tls1_2;

  final client = HttpClient(context: context)
    ..connectionFactory = (Uri uri, String? proxyHost, int? proxyPort) async {
      print("--- connectionFactory");
      print(uri);
      print(proxyHost);
      print(proxyPort);

      final ipList = await mySecureDnsLookup(uri.host);

      // TCP 接続
      final rawSocket = await Socket.connect(ipList.first, uri.port);

      // TLS 接続
      final secureSocket = SecureSocket.secure(rawSocket, host: uri.host,
          onBadCertificate: (X509Certificate cert) {
        print("--- onBadCertificate");
        print(cert.issuer);
        print(cert.subject);
        print(cert.pem);
        return false;
      });

      return Future.value(ConnectionTask.fromSocket(secureSocket, () {}));
    };

  final ioclient = IOClient(client);

  final url = 'https://example.com/';
//  final url = 'https://tls-v1-2.badssl.com/';
/*
  final request = await client.getUrl(Uri.parse(url));
  final response1 = await request.close();
  print(">>> HTTPClient");
  print('Response status: ${response1.statusCode}');
  print(response1.headers);
  print("");
  print(await utf8.decodeStream(response1));
  print("");
*/
  try {
    final request2 = http.Request('GET', Uri.parse(url))
      ..followRedirects = false;
    final response2 = await ioclient.send(request2);
    print(">>> IOClient");
    print('Response status: ${response2.statusCode}');
    print(response2.headers);
    print("");
    print(utf8.decode(await response2.stream.toBytes()));
    print("");
  } catch (e) {
    print("--- Exception");
    print(e);
  }

  ioclient.close();
}

Future<List<InternetAddress>> mySecureDnsLookup(String host) async {
  // ここに自前のDNSSECやDoHなどの処理を書く

  final res =
      await http.get(Uri.parse("https://8.8.8.8/resolve?name=${host}&type=A"));
  final a = jsonDecode(res.body);
  if (!a["AD"]) {
    print("Warning: DNSSECが対応していない");
  }

  List<InternetAddress> ips = [];
  for (var answer in a["Answer"]) {
    // TYPE == Aレコード
    if (answer["type"] == 1) {
      ips.add(InternetAddress(answer["data"]));
    }
  }

  return ips;
//  return [InternetAddress('23.192.228.84')];
//  return [InternetAddress('104.154.89.105')];
}
