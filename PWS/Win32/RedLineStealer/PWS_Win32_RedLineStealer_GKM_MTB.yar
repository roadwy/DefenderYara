
rule PWS_Win32_RedLineStealer_GKM_MTB{
	meta:
		description = "PWS:Win32/RedLineStealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b f7 c1 e6 04 03 b4 24 90 01 04 8d 0c 3b 33 f1 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}