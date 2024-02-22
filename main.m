/*
 * Snoolie K, (c) 2024.
 * Signs an unsigned shortcut with Apple ID context of another contact-signed shortcut.
 * This passes validation but crashes.
 * This is due to AEADecryptionInputStreamOpen not being able to open with the bad key.
 * Not a vulnerability, as since you don't have the private key it's not like you
 * can create an encrypted stream that would work...
 * Nonetheless, publishing since no one else is researching Shortcuts Signing.
*/

#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <getopt.h>
#include <dlfcn.h>
#include <unistd.h>
#include "libshortcutsign/libshortcutsign.h"

#define OPTSTR "i:a:o:hv"

extern char *optarg;

SecKeyRef generate_private_key(void) {
 NSMutableDictionary *mutableDict = [NSMutableDictionary dictionary];
 mutableDict[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeECSECPrimeRandom;
 mutableDict[(__bridge id)kSecAttrKeySizeInBits] = @256;  /* I *really* hope this is correct */
 mutableDict[(__bridge id)kSecAttrIsPermanent] = (__bridge id)kCFBooleanFalse;
 return SecKeyCreateRandomKey((__bridge CFDictionaryRef)mutableDict, 0);
}

int poc(char *inputPath, char *authPath, char *outputPath) {
 NSData *authData = auth_data_from_shortcut(authPath);
 if (!authData) {
  printf("poc failed to get auth data\n");
  return -1;
 }
 SecKeyRef privKey = generate_private_key();
 if (!privKey) {
  printf("poc failed to generate signing key\n");
  return -1;
 }
 return sign_shortcut_with_private_key_and_auth_data(privKey, authData, inputPath, outputPath);
}

void show_help(void) {
 printf("Usage: sign-mismatch-poc <options>\n\n");
 printf(" -i: (required) path to the unsigned shortcut to use as input\n");
 printf(" -a: (required) path to the contact signed shortcut with the auth data to use to sign\n");
 printf(" -o: (required) path to output the data (must not exist)\n");
 printf(" -v: (optional) verbose/show debug\n");
 printf(" -h: show usage\n");
}

int main(int argc, char *argv[]) {
 int opt;
 int accept = 0;
 char *inputPath;
 char *authPath;
 char *outputPath;

 while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
  /* probably should use a switch case for this, but i hate them */
  if (opt == 'i') {
   inputPath = optarg;
   accept++;
  } else if (opt == 'a') {
   authPath = optarg;
   accept++;
  } else if (opt == 'o') {
   outputPath = optarg;
   if (access(outputPath, F_OK) == 0) {
    printf("A file already exists on the output path.\n");
    exit(1);
   }
   accept++;
  } else if (opt == 'h') {
   /* Show help */
   show_help();
   return 0;
  }
 }
 if (accept == 3) {
  /* All args supplied - run poc */
  int isNotCorrectlySigned = verify_contact_signed_shortcut(authPath);
  if (isNotCorrectlySigned) {
   printf("Warning: Contact signed shortcut may not be valid (error %d)\n", isNotCorrectlySigned);
  }
  int pocerror = poc(inputPath, authPath, outputPath);
  if (pocerror) {
   fprintf(stderr,"poc failed (error %d)\n", pocerror);
   return -1;
  }
 } else {
  printf("Invalid arguments.\n");
  show_help();
 }
 
 return 0;
}
