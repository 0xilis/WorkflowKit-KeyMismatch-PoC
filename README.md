# WorkflowKit-KeyMismatch-PoC
Generate a signed shortcut file that makes Shortcuts crash.

### What's this?

A couple months ago, I decided to peek back at my awful decomps of the WorkflowKit source, and decided to touch up the method that extracts contact-signed shortcut files, that being `WFShortcutPackageFile`'s `preformShortcutDataExtractionWithCompletion:`.

I eventually got it to the point where hooking it with the decompiled version successfully extracted the shortcut. You can find the decomp here: [https://github.com/0xilis/RandomShortcutsRev/blob/aad03499a300e390199495417c021f76a60e00b7/WFShortcutPackageFile.m#L135C8-L135C51](https://github.com/0xilis/RandomShortcutsRev/blob/aad03499a300e390199495417c021f76a60e00b7/WFShortcutPackageFile.m#L135C8-L135C51).

I decided to try, you know what, this won't work, but why not, and sign a shortcut with the context containing the public key of another one. Interestingly enough, this actually passes validation, but no vuln here. This is because the shortcut data is encrypted with the private key, and even if validation passed, since our new shortcut is encrypted with a different key, it fails to extract; in fact, `AEADecryptionInputStreamOpen` will return nil, which WorkflowKit does not check for, which will cause a crash later on (not sure if this is a WorkflowKit issue and it should be checking that for nil or if this is with libAppleArchive itself and that `AAArchiveStreamProcess` should return a negative error code if there is no decryption stream).

Despite this, I'm still publishing this tool that allows you to replicate this, since I don't see anyone else messing with signed shortcut files. This was ran on macOS Monterey 12.6.

# Usage

(Use `sign-mismatch-poc -h` to see help)

```
Usage: sign-mismatch-poc <options>
 -i: filepath to the unsigned shortcut to use as input (required)
 -a: filepath to the contact signed shortcut with the auth data to use to sign (required)
 -o: filepath to output the data (required, must not exist)
 -v: (optional) verbose/show debug
```
