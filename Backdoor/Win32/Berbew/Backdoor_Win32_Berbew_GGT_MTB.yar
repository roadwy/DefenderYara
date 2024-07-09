
rule Backdoor_Win32_Berbew_GGT_MTB{
	meta:
		description = "Backdoor:Win32/Berbew.GGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {89 85 e8 fe ff ff 09 c0 74 50 89 d8 31 d8 89 c3 b8 ?? ?? ?? ?? f7 e3 89 85 ?? ?? ?? ?? 89 c3 31 d8 89 c3 } //10
		$a_02_1 = {89 d8 01 d8 89 c3 81 eb ?? ?? ?? ?? 89 d8 31 d8 89 c3 81 c3 ?? ?? ?? ?? 31 c0 40 e9 e9 } //10
		$a_01_2 = {4f 70 65 6e 4d 75 74 65 78 } //1 OpenMutex
		$a_01_3 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}