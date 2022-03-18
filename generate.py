import os
import sys
import getopt
from libwgopparser import Parser, errprint


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], 'hiko:', ["tmux"])
    opts = {p[0]: p[1] for p in opts}

    if '-h' in opts:
        print('''wg-ops: WireGuard configuration extended generator
OPTIONS
    -h Display this help and quit.
    -k Output generated config to standard output
    -o <filename> Output generated config to file. Default is {source_filename}.gen
    --tmux Use tmux instead of containers
HELP
    For latest help please view https://github.com/Kiritow/wg-ops
''')
        exit(0)

    filepath = args[0]
    filename = os.path.basename(filepath)

    with open(filepath, 'r') as f:
        content = f.read()

    wgop_basepath = os.path.dirname(os.path.realpath(sys.argv[0]))
    parser = Parser(wgop_basepath)
    if '-i' in opts:
        parser.opt_allow_modify = True
        parser.opt_source_path = filepath
    if '--tmux' in opts:
        parser.opt_use_tmux = True

    parser.parse(content)
    parser.compile_interface()
    parser.compile_peers()
    parser.compile_final()

    if '-k' in opts or ('-o' in opts and opts['-o'] == '-'):
        print(parser.get_result())
    elif '-o' in opts:
        errprint('Saving to {}...'.format(opts['-o']))
        with open(opts['-o'], 'w') as f:
            f.write(parser.get_result())
    else:
        errprint('Saving to {}.gen...'.format(filename))
        with open('{}.gen'.format(filename), 'w') as f:
            f.write(parser.get_result())
