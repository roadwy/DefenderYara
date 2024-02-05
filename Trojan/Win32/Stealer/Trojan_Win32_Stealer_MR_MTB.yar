
rule Trojan_Win32_Stealer_MR_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b f0 03 d0 d3 e0 c1 ee 90 01 01 03 b4 24 90 01 04 03 84 24 90 01 04 89 74 24 90 01 01 8b c8 e8 90 01 04 33 c6 89 84 24 90 01 04 89 2d 90 01 04 8b 84 24 90 01 04 29 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}