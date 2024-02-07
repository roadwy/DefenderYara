
rule Trojan_MacOS_ZURU_A{
	meta:
		description = "Trojan:MacOS/ZURU.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 38 38 38 38 38 38 38 38 38 20 63 6f 64 65 3a 40 25 40 } //01 00  ===========888888888 code:@%@
		$a_01_1 = {6d 79 4f 43 4c 6f 67 } //01 00  myOCLog
		$a_01_2 = {41 46 4e 65 74 77 6f 72 6b 69 6e 67 2f 41 46 48 54 54 50 53 65 73 73 69 6f 6e 4d 61 6e 61 67 65 72 } //01 00  AFNetworking/AFHTTPSessionManager
		$a_01_3 = {72 75 6e 53 68 65 6c 6c 57 69 74 68 43 6f 6d 6d 61 6e 64 3a 63 6f 6d 70 6c 65 74 65 42 6c 6f 63 6b } //01 00  runShellWithCommand:completeBlock
		$a_01_4 = {2f 55 73 65 72 73 2f 65 72 64 6f 75 2f 44 65 73 6b 74 6f 70 2f 6d 61 63 } //00 00  /Users/erdou/Desktop/mac
	condition:
		any of ($a_*)
 
}