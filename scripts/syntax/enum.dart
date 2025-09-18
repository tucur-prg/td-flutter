enum Command { start, stop, restart }

main(List<String> args) {
  print(args);
  try {
    print(Command.values.byName(args.first));
  } on ArgumentError catch (e) {
    print(e);
  }
}
