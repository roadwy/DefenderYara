
rule TrojanDownloader_BAT_Small_AB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_81_0 = {4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 } //3 MemberRefsProxy
		$a_81_1 = {57 65 62 52 65 73 70 6f 6e 73 65 } //3 WebResponse
		$a_81_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //3 HttpWebRequest
		$a_81_3 = {4d 54 51 7a 4d 77 3d 3d } //3 MTQzMw==
		$a_81_4 = {52 56 68 51 4c 6b 56 59 55 45 31 42 53 55 34 3d 31 51 } //3 RVhQLkVYUE1BSU4=1Q
		$a_81_5 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //3 SmartAssembly
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //3 DebuggingModes
		$a_81_7 = {63 61 70 78 } //3 capx
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3) >=24
 
}