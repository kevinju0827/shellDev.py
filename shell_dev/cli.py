from optparse import OptionParser
from .core import chk_mingw_toolkit, gen_shellcode

title = \
    """
          _          _ _ _____
         | |        | | |  __ \\
      ___| |__   ___| | | |  | | _____   __
     / __| '_ \\ / _ \\ | | |  | |/ _ \\ \\ / /
     \\__ \\ | | |  __/ | | |__| |  __/\\ V /
     |___/_| |_|\\___|_|_|_____/ \\___| \\_/

    v1.3 by aaaddress1@chroot.org
    """


def run():
    print(title)
    parser = OptionParser()
    parser.add_option("-s", "--src", dest="source",
                      help="shelldev c/c++ script path.", metavar="PATH")
    parser.add_option("-m", "--mgw", dest="mingwPath",
                      help="set mingw path, mingw path you select determine payload is 32bit or 64bit.", metavar="PATH")
    parser.add_option("--noclear",
                      action="store_true", dest="dontclear", default=False,
                      help="don't clear junk file after generate shellcode.")

    parser.add_option("-a", "--arch", dest="arch",
                      help="Arch - should be x86 or x64")

    parser.add_option("--jit",
                      action="store_true", dest="jit", default=False,
                      help="Just In Time Compile and Run Shellcode (as x86 Shellcode & Inject to Notepad for test, "
                           "require run as admin.)")

    (options, args) = parser.parse_args()
    if options.source is None or options.mingwPath is None or options.arch not in ['x86', 'x64']:
        parser.print_help()
    else:
        chk_mingw_toolkit(options.mingwPath)
        gen_shellcode(options.source, not options.dontclear, options.arch, options.jit)
