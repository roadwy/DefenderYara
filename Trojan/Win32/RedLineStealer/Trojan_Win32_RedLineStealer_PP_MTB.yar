
rule Trojan_Win32_RedLineStealer_PP_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 90 01 04 81 3d 90 01 08 c7 04 24 f0 43 03 00 75 08 6a 00 ff 15 90 01 04 56 83 44 24 04 0d a1 90 01 04 0f af 44 24 04 05 c3 9e 26 00 81 3d 90 01 04 81 13 00 00 a3 90 01 04 0f b7 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}