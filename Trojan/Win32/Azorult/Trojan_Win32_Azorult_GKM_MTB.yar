
rule Trojan_Win32_Azorult_GKM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {14 0f 3d 03 02 00 00 75 06 89 35 84 d1 7f 00 41 3b c8 72 90 09 14 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 88 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 81 e3 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00 75 [0-20] 30 1c ?? 83 ff 19 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}