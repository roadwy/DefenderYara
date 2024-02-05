
rule Trojan_Win32_RedLineStealer_PJ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 29 45 fc 8b 4d fc c1 e1 90 01 01 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc 90 01 06 ff 8b c2 c1 e8 90 01 01 03 45 e4 c7 05 90 01 08 89 45 08 33 45 0c 33 c1 2b f0 90 00 } //01 00 
		$a_03_1 = {8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 90 01 01 89 44 24 10 8b 44 24 10 03 44 24 44 c7 05 90 01 08 33 44 24 14 33 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}