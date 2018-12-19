import sys
import glob
import numpy as np
from pdb import set_trace as pdb

BASENORM=True


bench_col_dat = {
    "nullSyscall":2,
    "forkExit":2,
    "forkExec":2,
    "forkShell":3,
    "mmap":1,
    "pgFault":3,
    "openClose":2,
    "read":2,
    "write":2,
    "stat":2,
    "sigInstall":3,
    "sigDeliver":3,
    "select":4,
    "fcntl":3,
    "pipe":2
}


def main( argv ):

    if len(argv) < 3:
        print "Usage: python {} <search directory>  <file pattern> [<file pattern>]".format(argv[0])
        exit(1)

    # Store the file pattern
    search_dir = argv[1]
    patterns = argv[2:]
    # Output tabl
    bench_table = dict()

    pattern_dat = {}
    idx = 0

    # For each pattrn, we will output a column in the table
    for pattern in patterns:
        pathname = search_dir+"/"+pattern
        print "Searching in [{}]".format(pathname)
        # Get the list of files that match the pattern
        files = glob.glob(pathname)
        print files

        bname_set = set()
        
        # Loop through each file
        for fname in files:
            # Get bench ID by file name
            bname = fname.split("_",1)[0].rsplit('/',1)[1]
            bname_set.add(bname)
            # Fetch column number from dictionary
            colnum = bench_col_dat.get(bname, None)

            if not colnum:
                print "Skipping file: [{}]".format(fname)
                continue
            
            with open(fname, "r") as fp:
                print "Processing file: [{}]".format(fname)
                lines = fp.readlines()
                data = [float(x.split(' ')[colnum]) for x in lines]
                if ( len(data) < 2 ):
                    continue

                avg = np.mean(data)
                stddev = np.std(data,ddof=1)

                if ( bench_table.get(bname,None) == None ):
                    bench_table[bname] = { pattern:(avg, stddev) }
                else:
                    bench_table[bname][pattern] = (avg,stddev)


    print '\n\n'


    benchmarks = bench_table.keys()
    order = [8,9,5,10,2,14,1,6,11,12,13,3,4,7,0]
    order += [i for i in range(len(benchmarks)) if not (i in order)]
    benchmarks_ord = [benchmarks[i] for i in order]

    systems = bench_table[benchmarks[0]].keys()
    order = [1,3,4,0,2]
    order += [i for i in range(len(systems)) if not (i in order)]
    systems_ordered = [systems[i] for i in order]

    baseline = None
    print "(Benchmark) ",
    for system in systems_ordered:
        print "({}) ".format(system),
        if ( ('baseline' in system) and (baseline == None) ):
            baseline = system
    print ""

    for benchmark in benchmarks_ord:
        print benchmark, '&',
        for system in systems_ordered:
            #print "({}) ".format(system),
            if ( BASENORM and (not (baseline in system)) ):
                # Normailze to the baseline
                out = bench_table[benchmark][system][0] / bench_table[benchmark][baseline][0]
                print "{0:0.2f}x".format(out), '&',
                # Stddev as percentage of mean
                out = (bench_table[benchmark][system][1] / bench_table[benchmark][system][0])*100
                print "{0:0.2f}%".format(out), '&',
            else:
                # Absolute mean value
                print "{0:0.4f}".format(bench_table[benchmark][system][0]), '&',
                # Absolute standard deviation
                print "{0:0.4f}".format(bench_table[benchmark][system][1]), '&',
        print '\b\b\\\\'
        print '\\hline'


if __name__ == "__main__":
    main( sys.argv )
