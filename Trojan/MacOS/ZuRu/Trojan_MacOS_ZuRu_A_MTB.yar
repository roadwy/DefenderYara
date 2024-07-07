
rule Trojan_MacOS_ZuRu_A_MTB{
	meta:
		description = "Trojan:MacOS/ZuRu.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 6f 6f 6b 43 6f 6d 6d 6f 6e } //1 hookCommon
		$a_00_1 = {6d 79 4f 43 4c 6f 67 } //1 myOCLog
		$a_00_2 = {53 53 4c 50 69 6e 6e 69 6e 67 4d 6f 64 65 } //1 SSLPinningMode
		$a_00_3 = {72 75 6e 53 68 65 6c 6c 57 69 74 68 43 6f 6d 6d 61 6e 64 3a 63 6f 6d 70 6c 65 74 65 42 6c 6f 63 6b } //1 runShellWithCommand:completeBlock
		$a_00_4 = {2e 63 78 78 5f 64 65 73 74 72 75 63 74 } //1 .cxx_destruct
		$a_00_5 = {2f 63 6f 6d 70 69 6c 65 72 2d 72 74 2f 6c 69 62 2f 62 75 69 6c 74 69 6e 73 2f 6f 73 5f 76 65 72 73 69 6f 6e 5f 63 68 65 63 6b 2e 63 } //1 /compiler-rt/lib/builtins/os_version_check.c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}