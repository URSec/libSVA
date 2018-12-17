#!/bin/sh

# Number of repetitions given to lmbench
REPS=1000

# Number of benchmarking runs
NUM_ROUNDS=10

# Location of LMBench
DIR=/usr/local/lib/lmbench/bin/amd64-freebsd9.3

# Location of directories and files needed by test
TMPDIR=`pwd`

# Dummy file with random contents
FSDIR=/root/vmx_bench/scripts/results
DUMMY=random.file

# Capture date
TIMESTAMP=$(date '+%Y%m%d_%H%M%S');

#Specify if we want to run GHOSTING benchmarks
GHOST_BENCH=1

# Path to custom libc (for ghosting)  
GHOST_LIBC=/xdong/temp/lib/libc.so.7

if [ $GHOST_BENCH -eq 1 ]; then
    echo "Running Benchmarks with GHOSTING ENABLED"
else 
    echo "Running Benchmarks with GHOSTING DISABLED"
fi

# Disable core dumps because lmbench (particularly the fork+exec test) tends
# to creash when they're enabled. (We haven't yet figured out why, but it
# seems to run fine with dumps disabled.)
ulimit -c 0

echo "Generating Random Content File: $FSDIR/$DUMMY"
head -c 10000000 /dev/urandom > $FSDIR/$DUMMY
echo "Benchmark started on: $TIMESTAMP"

echo "Running benchmark: Syscalls"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/nullSyscall_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_syscall -N $REPS null 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_syscall -N $REPS null 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Fork+Exit"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/forkExit_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_proc -N $REPS fork 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_proc -N $REPS fork 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Fork+Exec"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/forkExec_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_proc -N $REPS exec 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_proc -N $REPS exec 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Fork+Shell"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/forkShell_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_proc -N $REPS shell 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_proc -N $REPS shell 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: MMap"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/mmap_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_mmap -N $REPS 1m $FSDIR/$DUMMY 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_mmap -N $REPS 1m $FSDIR/$DUMMY 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Pagefaults"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/pgFault_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_pagefault -N $REPS $FSDIR/$DUMMY 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_pagefault -N $REPS $FSDIR/$DUMMY 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Open/Close"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/openClose_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_syscall -N $REPS open 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_syscall -N $REPS open 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Read"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/read_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_syscall -N $REPS read 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_syscall -N $REPS read 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Write"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/write_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_syscall -N $REPS write 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_syscall -N $REPS write 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Stat"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/stat_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_syscall -N $REPS stat 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_syscall -N $REPS stat 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Context Switch"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/contextSwitch_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_ctx -N $REPS 0k 2 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_ctx -N $REPS 0k 2 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: SigHandler Install"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/sigInstall_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_sig -N $REPS install 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_sig -N $REPS install 2>&1 | tee -a $OUTFILE
  fi
done


echo "Running benchmark: SigHandler Delivery"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/sigDeliver_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_sig -N $REPS catch 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_sig -N $REPS catch 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Select"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/select_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_select -N $REPS file 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_select -N $REPS file 2>&1 | tee -a $OUTFILE
  fi
done
    
echo "Running benchmark: Fcntl Lock"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/fcntl_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_fcntl -N $REPS 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_fcntl -N $REPS 2>&1 | tee -a $OUTFILE
  fi
done

echo "Running benchmark: Pipe"
for i in $(seq 1 $NUM_ROUNDS)
do
  OUTFILE=$FSDIR/pipe_$TIMESTAMP
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_pipe -N $REPS 2>&1 | tee -a $OUTFILE
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_pipe -N $REPS 2>&1 | tee -a $OUTFILE
  fi
done
