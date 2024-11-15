
rule Trojan_Win32_BadIIS_EC_MTB{
	meta:
		description = "Trojan:Win32/BadIIS.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 74 74 70 4d 6f 64 52 65 73 70 44 4c 4c 78 36 34 2e 70 64 62 } //1 HttpModRespDLLx64.pdb
		$a_81_1 = {48 74 74 70 4d 6f 64 44 4c 4c 2e 64 6c 6c } //1 HttpModDLL.dll
		$a_81_2 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //1 WinHttpCrackUrl
		$a_81_3 = {44 65 62 75 67 42 72 65 61 6b } //1 DebugBreak
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}