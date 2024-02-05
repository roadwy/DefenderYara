
rule Trojan_Win32_Glupteba_OO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 89 90 02 03 8b 90 02 03 01 90 02 03 8b 90 02 03 c1 90 02 03 03 90 02 03 8d 90 02 03 33 90 02 03 81 3d 90 02 08 c7 05 90 02 08 90 18 31 90 02 03 81 3d 90 02 08 90 18 ff 15 90 02 04 8b 90 02 03 8d 90 02 03 e8 90 02 04 81 3d 90 02 08 75 90 00 } //01 00 
		$a_02_1 = {75 04 6a 00 ff d3 81 3d 90 02 08 75 04 6a 00 ff d5 56 e8 90 02 04 83 c6 08 83 ef 01 90 18 81 3d 90 00 } //01 00 
		$a_02_2 = {75 06 6a 00 6a 00 ff d7 e8 90 02 04 a1 90 02 04 46 3b f0 90 18 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}