/* Headers for WorkflowKit */
#import <Foundation/Foundation.h>

@interface WFFileRepresentation : NSObject
@property (readonly, nonatomic) NSData *data;
+(id)fileWithData:(id)arg1 ofType:(id)arg2 proposedFilename:(id)arg3;
+(id)fileWithURL:(id)arg1 options:(long long)arg2;
+(id)fileWithURL:(id)arg1 options:(long long)arg2 ofType:(id)arg3;
+(id)proposedFilenameForFile:(id)arg1 ofType:(id)arg2;
+(id)fileWithURL:(id)arg1 options:(long long)arg2 ofType:(id)arg3 proposedFilename:(id)arg4;
@end

@interface WFWorkflowFileDescriptor : NSObject
@property (readonly, nonatomic) WFFileRepresentation *file;
-(id)initWithFile:(id)file name:(id)name;
@end

@interface WFWorkflowFile : NSObject
-(id)recordRepresentationWithError:(NSError*)err;
-(id)initWithDescriptor:(id)fileDesc error:(NSError*)err;
-(id)initWithFileData:(id)fileData name:(id)name error:(NSError*)err;
@end

@interface WFP2PSignedShortcutFileExporter : NSObject
@property (readonly, nonatomic) WFFileRepresentation *signedShortcutFile;
-(void)exportWorkflowWithCompletion:(id)comp;
-(instancetype)initWithWorkflowRecord:(id)wfRecord;
@end