#!/usr/local/bin/zsh

#Check if we have sudo powers
if [ ! $(sudo echo 0) ]
then 
    echo "No sudo powers..." 
    exit;
fi

export SRC_ROOT=`pwd`
KERNNAME=shade_w_checks

# Enable setup steps
do_configure=0
do_buildsva=1
do_buildllvm=0
do_buildkern=1
do_nextboot=0
do_90=1
do_reboot=0

# configure options
VMX='yes'
VG='yes'
MPX='yes'
MMU='yes'
DMAP='yes'
ASID='no'
LLC='yes'
PGDEF='yes'

function rebuildkernel {
  pushd $SRC_ROOT/usr/src
  time make buildkernel INSTKERNNAME=$KERNNAME __MAKE_CONF=$SRC_ROOT/make.conf
  popd
}

function rebuildkernel_j32 {

  pushd $SRC_ROOT/usr/src
  time make buildkernel INSTKERNNAME=$KERNNAME __MAKE_CONF=$SRC_ROOT/make.conf -j32
  popd
}

function reinstallkernel {

  pushd $SRC_ROOT/usr/src
  sudo time make installkernel INSTKERNNAME=$KERNNAME __MAKE_CONF=$SRC_ROOT/make.conf
  popd

  echo Deleting old /sva90/boot/$KERNNAME...
  sudo rm -r /sva90/boot/$KERNNAME
  echo Moving /boot/$KERNNAME to /sva90/boot/$KERNNAME...
  sudo mv /boot/$KERNNAME /sva90/boot/

}

function rebuildsva {
  pushd $SRC_ROOT/SVA
  time make
  popd
}

function rebuildall {

  rebuildsva
  rebuildkernel
  reinstallkernel

  echo ----- Rebuild-All Complete -----
  echo Start time: $START_TIME
  echo Finish time: `date`
  echo --------------------------------
}


sudo_stat=~/.sudo.tmp
echo $$ >> $sudo_stat
trap 'rm -f $sudo_stat >/dev/null 2>&1' 0
trap "exit 2" 1 2 3 15

sudo_me() {
    while [ -f $sudo_stat ]; do
        sudo -v
        sleep 5
    done &
}

function cleanup {
    rm -f $sudo_stat
}
trap cleanup EXIT

# Set up sudo heartbeat
sudo_me

echo "Begin $SRC_ROOT Set up. Building for Kernel: $KERNNAME"

set -e

if [[ $do_configure -eq 1 ]]; then
    # ./configure --enable-targets=host \
	  #     --enable-vmx=$VMX \
    #     --enable-vg=$VG \
    #     --enable-mpx=$MPX \
    #     --enable-mmuchecks=$MMU \
    #     --enable-sva-dmap=$DMAP \
    #     --enable-asid=$ASID \
    #     --enable-llc-part=$LLC \
    #     --enable-pg-defenses=$PGDEF
    ./configure --enable-targets=host --enable-vg --enable-sva-dmap --enable-mpx --enable-llc-part --enable-pg-defenses
fi

if [[ $do_buildllvm -eq 1 ]]; then 
    pushd $SRC_ROOT/llvm
    gmake -j5
    popd
fi

if [[ $do_buildsva -eq 1 ]]; then 
    rebuildsva
fi

if [[ $do_buildkern -eq 1 ]]; then 
    rebuildkernel_j32
    reinstallkernel
fi

# cd lib/libc
# make && sudo make install
# cd ../../

# cd sbin/init
# sudo make && sudo make install
# cd ../../

# cd bin/sh
# sudo make && sudo make install
# cd ../../

rm $sudo_stat

if [[ $do_nextboot -eq 1 ]]; then 
    nextboot_cmd="sudo nextboot "
    #nextboot_cmd="$nextboot_cmd -o '-s' "
    if [[ $do_90 -eq 1 ]]; then
        nextboot_cmd="$nextboot_cmd -e currdev=disk0s1b: "
    fi

    nextboot_cmd="$nextboot_cmd -k $KERNNAME "
    eval $nextboot_cmd
fi

if [[ $do_90 -eq 1 ]]; then
    echo "Moving /boot/KERNNAME to /sva90/boot/$KERNNAME"
    sudo rm -rf /sva90/boot/$KERNNAME
    sudo mv -fv /boot/$KERNNAME /sva90/boot/
fi

echo "Done Setting up SVA."

if [[ $do_reboot -eq 1 ]]; then
    echo -n "Rebooting... in 3..."
    sleep 1
    echo -n " 2..."
    sleep 1
    echo -n " 1..."
    sleep 1

    sudo reboot
fi

