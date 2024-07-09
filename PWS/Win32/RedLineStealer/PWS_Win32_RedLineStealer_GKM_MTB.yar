
rule PWS_Win32_RedLineStealer_GKM_MTB{
	meta:
		description = "PWS:Win32/RedLineStealer.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b f7 c1 e6 04 03 b4 24 ?? ?? ?? ?? 8d 0c 3b 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}