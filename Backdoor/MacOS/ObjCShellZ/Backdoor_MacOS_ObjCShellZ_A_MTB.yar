
rule Backdoor_MacOS_ObjCShellZ_A_MTB{
	meta:
		description = "Backdoor:MacOS/ObjCShellZ.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 77 69 73 73 62 6f 72 67 2e 62 } //1 swissborg.b
		$a_00_1 = {6c 6f 67 2f 7a 78 63 76 2f 62 6e 6d } //1 log/zxcv/bnm
		$a_00_2 = {6f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 56 65 72 73 69 6f 6e 53 74 72 69 6e 67 } //1 operatingSystemVersionString
		$a_00_3 = {43 6f 6d 6d 61 6e 64 20 65 78 65 63 75 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Command executed successfully
		$a_00_4 = {73 65 6e 64 52 65 71 75 65 73 74 } //1 sendRequest
		$a_00_5 = {73 65 74 54 69 6d 65 72 } //1 setTimer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}