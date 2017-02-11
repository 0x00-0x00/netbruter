#!/bin/bash
# Written by zc00l
# Downloads all documentation from LINK
echo "Documentation downloader"
echo "------------------------"

function download_content
{
    if [[ $1 == "" ]]; then
        echo "Usage: $0 <LINK>";
        exit;
    fi
    echo "Documentation link: $1"
    echo -n "[+] Downloading documentation data ... "
    wget --convert-links -erobots=off -w 1 -nd -np -m $1 > /dev/null 2>&1
    if [[ $? != 0 ]]; then
        echo "FAIL";
    else
        echo "DONE";
    fi
    return 0;
}

download_content $1
