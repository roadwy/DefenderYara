
rule PWS_Win32_Recealer_GKM_MTB{
	meta:
		description = "PWS:Win32/Recealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c9 3b c6 76 90 01 01 8b 15 90 01 04 8a 94 0a 90 01 04 8b 3d 90 01 04 88 14 0f 3d 03 02 00 00 75 06 89 35 90 01 04 41 3b c8 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Recealer_GKM_MTB_2{
	meta:
		description = "PWS:Win32/Recealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ee 05 89 74 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 31 4c 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}