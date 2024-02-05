
rule Trojan_Win32_Redline_EXT_MTB{
	meta:
		description = "Trojan:Win32/Redline.EXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ee 8b 4c 24 28 89 44 24 2c 8d 44 24 1c 89 74 24 1c c7 05 90 01 04 ee 3d ea f4 e8 e7 fe ff ff 8b 44 24 2c 31 44 24 10 81 3d 90 01 04 e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 90 01 04 8b 4c 24 10 31 4c 24 1c 81 3d 90 01 04 13 02 00 00 75 90 00 } //01 00 
		$a_03_1 = {29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 90 01 04 8b 44 24 30 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 07 31 54 24 10 d3 e8 03 c3 81 3d 90 01 04 21 01 00 00 8b f0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}