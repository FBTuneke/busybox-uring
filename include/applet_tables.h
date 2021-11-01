/* This is a generated file, don't edit */

#define NUM_APPLETS 6
#define KNOWN_APPNAME_OFFSETS 0

const char applet_names[] ALIGN1 = ""
"cat" "\0"
"echo" "\0"
"sh" "\0"
"sleep" "\0"
"split" "\0"
"zcat" "\0"
;

#define APPLET_NO_cat 0
#define APPLET_NO_echo 1
#define APPLET_NO_sh 2
#define APPLET_NO_sleep 3
#define APPLET_NO_split 4
#define APPLET_NO_zcat 5

#ifndef SKIP_applet_main
int (*const applet_main[])(int argc, char **argv) = {
cat_main,
echo_main,
ash_main,
sleep_main,
split_main,
gunzip_main,
};
#endif

const uint8_t applet_suid[] ALIGN1 = {
0x00,
0x00,
};

const uint8_t applet_install_loc[] ALIGN1 = {
0x11,
0x11,
0x13,
};
