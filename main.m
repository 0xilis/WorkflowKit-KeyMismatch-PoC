/*
 * Snoolie K, (c) 2024.
 * Signs a unsigned shortcut with Apple ID context of another contact-signed shortcut.
 * This passes validation but crashes.
 * This is due to AEADecryptionInputStreamOpen not being able to open with the bad key.
 * Not a vulnerability, as since you don't have the private key it's not like you
 * can create an encrypted stream that would work...
 * Nonetheless, publishing since no one else is researching Shortcuts Signing.
 *
 * Code is awful, but it works...
*/

#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#import "aea.h"
#include <getopt.h>
#include <dlfcn.h>
#include <unistd.h>

#define OPTSTR "i:a:o:hv"

extern char *optarg;

/* Global Variables */
int verbose = 0;
char *authPath;

#define EZprintf(format,args...)        \
                  if (verbose) {      \ 
                      printf(format, ## args);    \
                  }
#define EZNSLog(format,args...)        \
                  if (verbose) {      \ 
                      NSLog(format, ## args);    \
                  }

id fake_generateAuthData(id self, SEL cmd) {
 EZprintf("reached fake_generateAuthData\n");
 NSData *authData = auth_data_from_path(authPath);
 EZNSLog(@"authData: %@",authData);
 return authData;
}

@interface Fake_WFShortcutSigningContext : NSObject
-(id)generateAuthData;
@end

@implementation Fake_WFShortcutSigningContext
-(id)generateAuthData {
 return fake_generateAuthData(0, 0);
}
@end

static int (*orig_call)(id self, SEL cmd, id privateKey, id signingContext, id error);

int debug_hook(id self, SEL cmd, id privateKey, id signingContext, id error) {
 EZprintf("reached debug_hook\n");
 EZNSLog(@"privateKey: %@", privateKey);
 EZNSLog(@"signingContext: %@", signingContext);
 return orig_call(self, cmd, privateKey, [[Fake_WFShortcutSigningContext alloc]init], error);
}

#import "WorkflowKit.h"

@interface Fake_WFWorkflowRecord : NSObject
@property (readwrite) WFWorkflowFile *fileRepresentation;
-(NSString *)name;
@end

@implementation Fake_WFWorkflowRecord
-(NSString *)name {
 return @"Fake_WFWorkflowRecord";
}
@end

int poc(char *inputPath, char *authPath, char *outputPath) {
 EZprintf("start\n");
 NSBundle *container = [NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"];
 if ([container load]) {
  EZprintf("WorkflowKit loaded.\n");
  /* get classes */
  Class WFWorkflowFileDescriptorClass = objc_getClass("WFWorkflowFileDescriptor");
  Class WFWorkflowFileClass = objc_getClass("WFWorkflowFile");
  Class WFP2PSignedShortcutFileExporterClass = objc_getClass("WFP2PSignedShortcutFileExporter");
  Class WFFileRepresentationClass = objc_getClass("WFFileRepresentation");
  
  /* get WFWorkflowRecord from file */
  WFFileRepresentation *fileRep = [WFFileRepresentationClass fileWithURL:[NSURL fileURLWithPath:[NSString stringWithUTF8String:inputPath]] options:nil];
  WFWorkflowFileDescriptor *fileDesc = [[WFWorkflowFileDescriptorClass alloc] initWithFile:fileRep name:@"SnoolieShortcut"];
  WFWorkflowFile *wFile = [[WFWorkflowFileClass alloc] initWithDescriptor:fileDesc error:nil];
  //WFWorkflowRecord *workflowRecord = [wFile recordRepresentationWithError:nil]; /* requires cloudkit entitlement */
  Fake_WFWorkflowRecord *wfRecord = [[Fake_WFWorkflowRecord alloc]init];
  [wfRecord setFileRepresentation:wFile];

  /* hooks */
  orig_call = class_replaceMethod(objc_getClass("WFShortcutPackageFile"),sel_getUid("generateSignedShortcutFileRepresentationWithPrivateKey:signingContext:error:"),&debug_hook,0);
  class_replaceMethod(objc_getClass("WFShortcutSigningContext"),sel_getUid("generateAuthData"),&fake_generateAuthData,0);

 /* now actually sign shortcut */
 WFP2PSignedShortcutFileExporter *exporter = [[WFP2PSignedShortcutFileExporterClass alloc] initWithWorkflowRecord:wfRecord];
 [exporter exportWorkflowWithCompletion:^(id arg0, id arg1){
  EZNSLog(@"Completion block called");
  EZNSLog(@"arg1: %@",arg1);
 }];
 WFFileRepresentation *signedShortcutFile = [exporter signedShortcutFile];
 EZNSLog(@"signedShortcutFile: %@", signedShortcutFile);
 NSData *signedShortcutFileData = [signedShortcutFile data];
 [signedShortcutFileData writeToFile:[NSString stringWithUTF8String:outputPath] atomically:YES];

 } else {
  fprintf(stderr,"WorkflowKit failed to load.\n");
  exit(1);
 }
 return 0;
}

void show_help(void) {
 printf("Usage: sign-mismatch-poc <options>\n\n");
 printf(" -i: filepath to the unsigned shortcut to use as input (required)\n");
 printf(" -a: filepath to the contact signed shortcut with the auth data to use to sign (required)\n");
 printf(" -o: filepath to output the data (required, must not exist)\n");
 printf(" -v: (optional) verbose/show debug\n");
}

int main(int argc, char *argv[]) {
 int opt;
 int accept = 0;
 char *inputPath;
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
  } else if (opt == 'v') {
   verbose = 1;
  }
 }
 if (accept == 3) {
  /* All args supplied - run poc */
  poc(inputPath, authPath, outputPath);
 } else {
  printf("Invalid arguments.\n");
  show_help();
 }
 
 return 0;
}
