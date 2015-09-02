#!/bin/bash
#
# This script start top and privoxy proxy to route whole traffice through tor.
#

INTERFACE=Wi-Fi
BOTO_CONF=~/.boto

startTorAndPrivoxy() {
    # Start Privoxy
    v=`ps -ef | grep privoxy | grep -v grep`
    if [ -z "`echo $v | grep no-daemon`" ]; then
        sudo /usr/local/sbin/privoxy /usr/local/etc/privoxy/config
    fi

    # Start Tor
    v=`ps -ef | grep " tor" | grep -v grep`
    if [ -z "$v" ]; then
        sudo -u daemon tor
    fi
}

startUsingProxy() {
    # Configure your interface.
    networksetup -setwebproxy $INTERFACE 127.0.0.1 8118
    networksetup -setwebproxystate $INTERFACE on
    networksetup -setsecurewebproxy $INTERFACE 127.0.0.1 8118
    networksetup -setsecurewebproxystate $INTERFACE on
}

stopUsingProxy() {
    networksetup -setwebproxystate $INTERFACE off
    networksetup -setsecurewebproxystate $INTERFACE off
}

startTorAndPrivoxy

case $1 in
start)
     startUsingProxy
     cat << __END__ >> $BOTO_CONF
[Boto]
debug = 0
num_retries = 10

proxy = localhost
proxy_port = 8118
__END__
     ;;
stop)
     stopUsingProxy
     rm -f $BOTO_CONF
     ;;
esac


