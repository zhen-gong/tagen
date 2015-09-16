#!/bin/bash
#
# This script start test run. As an option it can route traffic through top and
# privoxy proxy.
#

# INTERFACE=Wi-Fi
BOTO_CONF=~/.boto

startTorAndPrivoxy() {
    # Start Privoxy
    v=`ps -ef | grep privoxy | grep -v grep | cut -f2`
    if [ -z "`echo $v | grep no-daemon`" ]; then
        sudo /usr/sbin/privoxy /etc/privoxy/config
    fi

    # Start Tor
    v=`ps -ef | grep " tor" | grep -v grep`
    if [ -z "$v" ]; then
        sudo -u daemon tor
    fi
}

startUsingProxy() {
     cat << __END__ >> $BOTO_CONF
[Boto]
debug = 0
num_retries = 10

proxy = localhost
proxy_port = 8118
__END__
#    Commented are commands for MAC
#    networksetup -setwebproxy $INTERFACE 127.0.0.1 8118
#    networksetup -setwebproxystate $INTERFACE on
#    networksetup -setsecurewebproxy $INTERFACE 127.0.0.1 8118
#    networksetup -setsecurewebproxystate $INTERFACE on
}

stopUsingProxy() {
#    Commented are commands for MAC
#    networksetup -setwebproxystate $INTERFACE off
#    networksetup -setsecurewebproxystate $INTERFACE off
     rm -f $BOTO_CONF
}

startTorAndPrivoxy

if [ "$1" == user_proxy]; then
     startUsingProxy
fi
echo "Starting python..."
python AWS/test_runner.py
echo "All tests are done."
stopUsingProxy

