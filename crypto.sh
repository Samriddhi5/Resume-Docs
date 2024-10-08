#!/bin/bash

help_func() {
if [ "$#" -ne 7 ] || [ "$#" -ne 5 ]; then # checking if the user is providing correct no. of arguments
    echo "Incorrect number of arguments."
    echo "Please provide arguments for sender in this format:- ./crypto.sh -sender receiver1.pub receiver2.pub receiver3.pub sender.priv plaintext_file zip_file"
    echo "Please provide arguments for receiver in this format:- ./crypto.sh -receiver receiver<#>.priv sender.pub zip_file plaintext_file"
    exit 1
fi
}

error_func() { #printing all the error messages to stderr
    echo "ERROR lnu.samr: $1" >&2
    exit 1
}

# function to perform encryption and signing on sender's side
senders_part() { #assigning arguments to each input file
    receiver1_pub=$1
    receiver2_pub=$2
    receiver3_pub=$3
    sender_priv=$4
    plaintext_file=$5
    zip_file=$6

    #Session Key Generation
    openssl rand -base64 128 > symm.key || error_func "Failed to generate a session key." # generating a random session key
    echo "Session Key Generated."

    #Plaintext Encryption
    openssl enc -aes-256-cbc -pbkdf2 -e -in "$plaintext_file" -out file1.enc -pass file:symm.key &>/dev/null || error_func "Failed to encrypt file1." # encrypting file1 with the generated session key using AES-256-CBC encryption mode
    echo "Plaintext Encrypted."

    #Hashing and Signing
    openssl dgst -sha256 -sign "$sender_priv" -out file.enc.sign file1.enc &>/dev/null || error_func "Failed to sign encrypted file." # hashing and signing the encrypted file using the sender's private key
    echo "Hashed and Signed."

    #Generating Secret Keys
    openssl pkeyutl -derive -inkey "$sender_priv" -peerkey "$receiver1_pub" -out symm_receiver1.enc &>/dev/null || error_func "Failed to derive shared key for receiver1." #generating shared keys and encrypt session key for each receiver
    openssl pkeyutl -derive -inkey "$sender_priv" -peerkey "$receiver2_pub" -out symm_receiver2.enc &>/dev/null || error_func "Failed to derive shared key for receiver2."
    openssl pkeyutl -derive -inkey "$sender_priv" -peerkey "$receiver3_pub" -out symm_receiver3.enc &>/dev/null || error_func "Failed to derive shared key for receiver3."
    echo "Secrets Generated."

    #Creating Envelopes
    openssl enc -aes-256-cbc -pbkdf2 -e -in symm.key -out env1 -pass file:symm_receiver1.enc &>/dev/null || error_func "Failed to Create Digital Signature Envelope."
    openssl enc -aes-256-cbc -pbkdf2 -e -in symm.key -out env2 -pass file:symm_receiver2.enc &>/dev/null || error_func "Failed to Create Digital Signature Envelope."
    openssl enc -aes-256-cbc -pbkdf2 -e -in symm.key -out env3 -pass file:symm_receiver3.enc &>/dev/null || error_func "Failed to Create Digital Signature Envelope."
    echo "Envelopes Generated."

    #Zipping Files
    zip "$zip_file" file1.enc file.enc.sign env* &>/dev/null || error_func "Failed to zip files." # zipping the encrypted files
    echo "Files Zipped."

    #Removing Files
    rm file1.enc file.enc.sign symm_receiver* env*
    echo "Files Removed."
}

# function to perform decryption and signature verification on receiver's side
receivers_part() { #assigning arguments to each input file
    receiver_priv=$1
    sender_pub=$2
    zip_file=$3
    plaintext_file=$4

    #Unzipping
    unzip -o "$zip_file" &>/dev/null || error_func "Failed to unzip files." # unzipping the received files
    echo "Files are unzipped."

    #Verifying
    if ! openssl dgst -sha256 -verify "$sender_pub" -signature file.enc.sign file1.enc &>/dev/null; then
        error_func "Failed to verify signature." # verifying the signature using the sender's public key
    fi
    echo "Signature verified."

    #Checking if the number of extracted files is less than expected
    expected_files=4  # Assuming 4 files: file1.enc, file.enc.sign, env*, symm_receiver*
    actual_files=$(ls | wc -l)
    if [ "$actual_files" -lt "$expected_files" ]; then
        error_func "Less files detected while unzipping than expected."
    fi

    #Generating Secret Key
    openssl pkeyutl -derive -inkey "$receiver_priv" -peerkey "$sender_pub" -out symm_receiver1.enc &>/dev/null || error_func "Failed to derive shared key." # deriving a shared key and decrypting the session key
    echo "Secret key generated."

    #Retriving Session Key
    if $(openssl enc -aes-256-cbc -pbkdf2 -d -in env1 -out symm.key -pass file:symm_receiver1.enc &>/dev/null); then
        echo "Decrypted Symmetric Key"
    elif $(openssl enc -aes-256-cbc -pbkdf2 -d -in env2 -out symm.key -pass file:symm_receiver1.enc &>/dev/null); then
        echo "Decrypted Symmetric Key"
    elif $(openssl enc -aes-256-cbc -pbkdf2 -d -in env3 -out symm.key -pass file:symm_receiver1.enc &>/dev/null); then
        echo "Decrypted Symmetric Key."
    else
        error_func "Could not find envelope."
    fi

    #Decrypting Encrypted File
    openssl enc -aes-256-cbc -pbkdf2 -d -in file1.enc -out "$plaintext_file" -pass file:symm.key &>/dev/null || error_func "Failed to decrypt message file." # decrypting the encrypted message file using the above generated session key

    #removing unwanted files
    rm file1.enc file.enc.sign symm_receiver* env* symm.key
    echo "Files Removed"
}

main() { #main function
    if [ "$#" -lt 5 ]; then
        error_func "Incorrect number of arguments."
    fi
    mode=$1
    if [ "$mode" == "-sender" ]; then
        help_func "$@"
        senders_part "${@:2}"
    elif [ "$mode" == "-receiver" ]; then
        help_func "$@"
        receivers_part "${@:2}"
    else
        error_func "Invalid mode! Please use -sender or -receiver."
    fi
}

main "$@" # calling the main function with command-line arguments
