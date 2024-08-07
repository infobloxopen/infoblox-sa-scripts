#!/bin/bash


# Exit the script as soon as a command fails
set -e


#region Check prerequisites
declare -a tools=(
"curl"
"unzip"
"python3"
"ssh"
"awk"
"sha256sum"
"eval"
"ps"
)
missing_tools=0

for tool in "${tools[@]}"; do
    if command -v $tool >/dev/null 2>&1; then
        echo "'$tool' is installed."
    else
        echo "[!!!] '$tool' is not installed."
        missing_tools=$((missing_tools+1))
    fi
done

if [ $missing_tools -ne 0 ]; then
    echo "Some tools are missing. Exiting."
    exit 1
fi
#endregion /Check prerequisites


#region Hard-coded variables
DOWNLOAD_URL="https://github.com/infobloxopen/infoblox-sa-scripts/releases/download/isc-v1.1.2.0/SLSENB_ISC_CS_1.1.2.0.tags-v1.1.2.d34c4eb.zip"
EXPECTED_HASH="E3A3270CAD67B58DB0D7585CDDA909486B418F2A9F34673F8F07329E9BEA0C27"
DESTINATION_FOLDER="./ib-isc-cs"

if [ -d "$DESTINATION_FOLDER" ]; then
  rm -r "$DESTINATION_FOLDER"
fi
#endregion /Hard-coded variables


echo "Creating directory './ib-isc-cs'."
mkdir -p "./ib-isc-cs"


# Download the zip file with curl
echo "Downloading artifact."
curl -Lo "$DESTINATION_FOLDER/ib-isc-cs.zip" "$DOWNLOAD_URL"


# Check Hashsum
echo "Checking hashsum for downloaded artifact."
ACTUAL_HASH=$(sha256sum "$DESTINATION_FOLDER/ib-isc-cs.zip" | awk '{print $1}')
if [[ "${actual_hash}" == "${expected_hash}" ]]; then
    echo "Hash check passed."
else
    echo "Hash check failed. Exiting."
    exit 1
fi


# Unzip the downloaded file
echo "Extracting artifact."
unzip "$DESTINATION_FOLDER/ib-isc-cs.zip" -d "$DESTINATION_FOLDER"


echo " "
echo "Setting executable flags on scripts."
chmod +x "$DESTINATION_FOLDER/isc_cs_run-solution.sh"
chmod +x "$DESTINATION_FOLDER/packer-script/dhcp-ib-isc-packer.sh"
chmod +x "$DESTINATION_FOLDER/packer-script/dns-ib-isc-packer.sh"


# Create a new Python virtual environment in the .venv folder
echo "Creating Python virtual environment."
python3 -m venv "$DESTINATION_FOLDER/.venv"


echo "Activating virtual environment."
cd "$DESTINATION_FOLDER"
. ./.venv/bin/activate


echo "Removing artifact archive."
rm ib-isc-cs.zip


echo "Installing packages."
python install-packages.py


# Final output
echo " "
echo "Solution downloaded and extracted to the './ib-isc-cs' directory."
echo " "
echo "Usage instructions:"
echo "    [!!!] Please find detailed usage instructions in $DESTINATION_FOLDER/README.md."
echo " "
echo "    Quick run:"
echo "    cd $DESTINATION_FOLDER"
echo "    ./isc_cs_run-solution.sh --mode|-m <dns|dhcp> --scenario|-s <local|packer|ssh|mount> [--server|-c <servers list>] [--path|-p <path>] ... [<repeat set of parameters>]"
echo " "
echo "    Examples:"
echo "    ./isc_cs_run-solution.sh --mode dns --scenario ssh --server 10.10.6.30,10.10.6.31"
echo "    ./isc_cs_run-solution.sh -m dns -s packer -p /home/user/data/"
echo "    ./isc_cs_run-solution.sh --mode dns --scenario ssh --server 10.10.6.30,10.10.6.31 --mode dhcp --scenario local"
