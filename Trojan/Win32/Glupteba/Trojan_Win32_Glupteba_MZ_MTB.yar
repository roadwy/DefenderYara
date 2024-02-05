
rule Trojan_Win32_Glupteba_MZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 3c 28 c1 e8 05 89 44 24 14 c7 05 90 02 08 8b 44 24 38 01 44 24 14 81 3d 90 00 } //01 00 
		$a_00_1 = {33 f7 31 74 24 14 8b 44 24 14 29 44 24 18 81 3d } //02 00 
		$a_02_2 = {8b f0 8d 14 28 d3 e0 c1 ee 05 03 90 02 06 03 90 02 06 89 90 02 06 8b c8 e8 90 02 04 33 c6 89 90 02 06 c7 05 90 02 08 8b 90 02 06 29 90 02 06 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}