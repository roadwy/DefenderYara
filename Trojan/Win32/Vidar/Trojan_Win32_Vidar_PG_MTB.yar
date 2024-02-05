
rule Trojan_Win32_Vidar_PG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 45 90 01 01 c7 05 90 01 04 19 36 6b ff 33 45 0c 33 f8 89 7d f4 8b 45 f4 29 45 fc 89 75 f8 8b 45 d8 01 45 f8 2b 5d f8 ff 4d ec 89 5d e8 90 00 } //01 00 
		$a_03_1 = {8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e8 8b 45 f4 81 45 e0 90 01 04 33 c1 2b f8 83 6d d8 01 89 45 f4 89 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}