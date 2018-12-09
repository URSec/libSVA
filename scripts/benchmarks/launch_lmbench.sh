#!/bin/sh

# Number of repetitions given to lmbench
REPS=1000

# Number of benchmarking runs
NUM_ROUNDS=10

# Ouput file directory
RESULTS_DIR=./results

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
head -c 10000000 /dev/urandom > $RESULTS_DIR/$DUMMY
echo "Benchmark started on: $TIMESTAMP"

echo "Running benchmark: Syscalls"
# System call latency
for i in $(seq 1 10)
do
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_syscall -N $REPS null 2>&1 | tee -a $RESULTS_DIR/nullSyscall_$TIMESTAMP
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_syscall -N $REPS null 2>&1 | tee -a $RESULTS_DIR/nullSyscall_$TIMESTAMP
  fi
done

# fork
echo "Running benchmark: Fork"
for i in $(seq 1 10)
do
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_proc -N $REPS fork 2>&1 | tee -a $RESULTS_DIR/forkSyscall_$TIMESTAMP
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_proc -N $REPS fork 2>&1 | tee -a $RESULTS_DIR/forkSyscall_$TIMESTAMP
  fi
done

# fork+exec
echo "Running benchmark: Fork+Exec"
for i in $(seq 1 10)
do
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_proc -N $REPS exec 2>&1 | tee -a $RESULTS_DIR/execSyscall_$TIMESTAMP
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_proc -N $REPS exec 2>&1 | tee -a $RESULTS_DIR/execSyscall_$TIMESTAMP
  fi
done

# mmap
echo "Running benchmark: MMap"
for i in $(seq 1 10)
do
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_mmap -N $REPS 1m $FSDIR/$DUMMY 2>&1 | tee -a $RESULTS_DIR/mmapSyscall_$TIMESTAMP
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_mmap -N $REPS 1m $FSDIR/$DUMMY 2>&1 | tee -a $RESULTS_DIR/mmapSyscall_$TIMESTAMP
  fi
done

# pagefault
echo "Running benchmark: Pagefaults"
for i in $(seq 1 10)
do
  if [ $GHOST_BENCH -eq 0 ]; then
      $DIR/lat_pagefault -N $REPS $FSDIR/$DUMMY 2>&1 | tee -a $RESULTS_DIR/pgSyscall_$TIMESTAMP
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC $DIR/lat_pagefault -N $REPS $FSDIR/$DUMMY 2>&1 | tee -a $RESULTS_DIR/pgSyscall_$TIMESTAMP
  fi
done

echo "Running benchmark: Open/Close"
# Open/Close Test
for i in $(seq 1 10)
do
  if [ $GHOST_BENCH -eq 0 ]; then
      /xdong/lmbench_bin/lat_syscall -N $REPS open 2>&1 | tee -a $RESULTS_DIR/openSyscall_$TIMESTAMP
  else
      GHOSTING=1 LD_PRELOAD=$GHOST_LIBC /xdong/lmbench_bin/lat_syscall -N $REPS open 2>&1 | tee -a $RESULTS_DIR/openSyscall_$TIMESTAMP
  fi
done

# Context switching Test
#for i in $(seq 1 10)
#do
#  $DIR/lat_ctx -N $REPS 0k 2 2>&1 | tee -a ctx
#done


# Creating/remove files
#for i in $(seq 1 10)
#do
#  echo "Running lat_fs: $i"
#  $DIR/lat_fs -N $REPS $FSDIR/tmp 2>&1 | tee -a fsSyscall
#done

