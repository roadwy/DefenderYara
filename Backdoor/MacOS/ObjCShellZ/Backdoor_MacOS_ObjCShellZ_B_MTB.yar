
rule Backdoor_MacOS_ObjCShellZ_B_MTB{
	meta:
		description = "Backdoor:MacOS/ObjCShellZ.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 77 69 73 73 62 6f 72 67 2e 62 6c 6f 67 2f 7a 78 63 76 2f 62 6e 6d } //1 swissborg.blog/zxcv/bnm
		$a_00_1 = {73 65 74 48 54 54 50 4d 65 74 68 6f 64 } //1 setHTTPMethod
		$a_00_2 = {43 6f 6d 6d 61 6e 64 20 65 78 65 63 75 74 65 64 } //1 Command executed
		$a_00_3 = {6d 61 69 6e 52 75 6e 4c 6f 6f 70 } //1 mainRunLoop
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}