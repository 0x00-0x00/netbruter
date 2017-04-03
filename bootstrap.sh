#!/bin/bash
# NetBruter bootstrap script of installation. 
#      Written by zc00l

uid=$(id -u)
project_name="netbruter"

function check_root
{
    if [[ $1 -eq 0 ]]; then
        return 0;
    else
        echo "[!] You do not have enough permissions to run this script."
        exit
    fi
}

function check_python
{
    py=$(python3.6 -V)
    if [[ $? != 0 ]]; then
        echo "[!] Python 3.6 is not installed or not in PATH.";
        exit;
    else
        pydir=$(which python3.6)
        echo -n "[+] Python 3.6 found: ";
        echo $pydir;
    fi
}

function check_pip
{
    pip=$(pip3.6 -V);
    if [[ $? != 0 ]]; then
        echo "[!] pip3.6 is not installed or not in PATH.";
        exit
    else
        pipdir=$(which pip3.6)
        echo -n "[+] pip3.6 found: ";
        echo $pipdir;
    fi
}

function install
{
    echo -n "[+] Installing dependencies ... "
    pip3.6 install -r requirements.txt > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo "OK";
    else
        echo "FAIL";
        exit;
    fi

    echo -n "[+] Installing ${project_name} ... "
    python3.6 setup.py install > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo "OK";
    else
        echo "FAIL";
        exit;
    fi
}

echo "NetBruter bootstrap install script"
echo "----------------------------------"
check_root ${uid}
check_python
check_pip
install
