
rule TrojanDownloader_BAT_Small_AB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 } //03 00  MemberRefsProxy
		$a_81_1 = {57 65 62 52 65 73 70 6f 6e 73 65 } //03 00  WebResponse
		$a_81_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //03 00  HttpWebRequest
		$a_81_3 = {4d 54 51 7a 4d 77 3d 3d } //03 00  MTQzMw==
		$a_81_4 = {52 56 68 51 4c 6b 56 59 55 45 31 42 53 55 34 3d 31 51 } //03 00  RVhQLkVYUE1BSU4=1Q
		$a_81_5 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //03 00  SmartAssembly
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //03 00  DebuggingModes
		$a_81_7 = {63 61 70 78 } //00 00  capx
	condition:
		any of ($a_*)
 
}