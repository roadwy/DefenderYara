
rule Trojan_MacOS_CloudMensis_A_MTB{
	meta:
		description = "Trojan:MacOS/CloudMensis.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 63 72 79 70 74 4d 79 46 69 6c 65 3a 65 6e 63 72 79 70 74 3a 6b 65 79 3a 61 66 74 65 72 44 65 6c 65 74 65 } //01 00  EncryptMyFile:encrypt:key:afterDelete
		$a_00_1 = {55 70 6c 6f 61 64 46 69 6c 65 49 6d 6d 65 64 69 61 74 65 6c 79 3a 43 4d 44 3a 64 65 6c 65 74 65 } //01 00  UploadFileImmediately:CMD:delete
		$a_00_2 = {43 72 65 61 74 65 50 6c 69 73 74 46 69 6c 65 41 74 3a 77 69 74 68 4c 61 62 65 6c 3a 65 78 65 50 61 74 68 3a 65 78 65 54 79 70 65 3a 6b 65 65 70 41 6c 69 76 65 } //01 00  CreatePlistFileAt:withLabel:exePath:exeType:keepAlive
		$a_00_3 = {45 78 65 63 75 74 65 43 6d 64 41 6e 64 53 61 76 65 52 65 73 75 6c 74 3a 73 61 76 65 52 65 73 75 6c 74 3a 75 70 6c 6f 61 64 49 6d 6d 65 64 69 61 74 65 6c 79 } //01 00  ExecuteCmdAndSaveResult:saveResult:uploadImmediately
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 2e 63 6f 6d 2e 61 70 70 6c 65 2e 57 69 6e 64 6f 77 53 65 72 76 65 72 2e 70 6c 69 73 74 } //01 00  /Library/LaunchDaemons/.com.apple.WindowServer.plist
		$a_00_5 = {2f 56 6f 6c 75 6d 65 73 2f 44 61 74 61 2f 4c 65 6f 6e 57 6f 72 6b 2f 4d 61 69 6e 54 61 73 6b 2f 42 61 44 2f 65 78 65 63 75 74 65 2f 65 78 65 63 75 74 65 2f } //00 00  /Volumes/Data/LeonWork/MainTask/BaD/execute/execute/
	condition:
		any of ($a_*)
 
}