
rule Trojan_Win32_Glupteba_SHG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c2 2b f0 8b c6 c1 e0 90 01 01 89 75 f0 89 45 fc 8b 45 d4 01 45 fc 8b 4d f8 03 fe d3 ee 89 7d 90 01 01 03 75 d8 8b 45 e4 31 45 fc 81 3d 74 d6 81 00 03 0b 00 00 75 90 00 } //01 00 
		$a_03_1 = {31 75 fc 8b 45 fc 29 45 ec 81 45 f4 90 01 04 ff 4d e0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}