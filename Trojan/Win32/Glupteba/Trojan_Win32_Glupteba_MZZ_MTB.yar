
rule Trojan_Win32_Glupteba_MZZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea c7 05 90 01 04 ee 3d ea f4 03 55 d8 8b 45 f0 31 45 fc 33 55 fc 89 55 f0 8b 45 f0 83 45 f4 64 29 45 f4 83 6d f4 64 83 3d 90 01 04 0c 75 90 00 } //01 00 
		$a_03_1 = {8b c2 d3 e8 8b 4d fc 8d 34 13 81 c3 90 01 04 03 45 e0 33 c6 33 c8 2b f9 83 6d 90 01 01 01 89 4d fc 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}