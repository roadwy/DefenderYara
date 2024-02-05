
rule Trojan_Win32_Vidar_PBH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 90 01 04 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01 59 90 00 } //02 00 
		$a_03_1 = {57 8d 4c 24 90 01 01 89 44 24 90 01 01 c7 05 90 01 08 e8 90 01 04 8b 44 24 18 33 44 24 14 c7 05 90 01 08 2b f0 89 44 24 18 8b c6 c1 e0 04 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}