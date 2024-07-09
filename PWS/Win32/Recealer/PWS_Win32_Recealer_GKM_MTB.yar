
rule PWS_Win32_Recealer_GKM_MTB{
	meta:
		description = "PWS:Win32/Recealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c9 3b c6 76 ?? 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 88 14 0f 3d 03 02 00 00 75 06 89 35 ?? ?? ?? ?? 41 3b c8 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Recealer_GKM_MTB_2{
	meta:
		description = "PWS:Win32/Recealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ee 05 89 74 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}