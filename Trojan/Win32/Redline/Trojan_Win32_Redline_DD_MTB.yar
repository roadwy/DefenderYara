
rule Trojan_Win32_Redline_DD_MTB{
	meta:
		description = "Trojan:Win32/Redline.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 8c 02 3b 2d 0b 00 88 0c 30 40 3b 05 1c 35 49 00 72 ed } //1
		$a_01_1 = {8b 44 24 24 01 44 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 1c 89 44 24 14 8b 4c 24 18 8b c6 d3 e8 89 44 24 10 8b 44 24 3c 01 44 24 10 33 54 24 14 8d 4c 24 2c 89 54 24 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_DD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 80 b6 90 01 05 6a 00 ff d7 80 86 90 01 05 6a 00 ff d7 80 86 90 01 05 6a 00 ff d7 80 b6 90 01 05 6a 00 ff d7 80 86 90 01 05 6a 00 ff d7 80 86 90 01 05 6a 00 ff d7 80 86 90 01 05 6a 00 ff d7 80 86 90 01 05 6a 00 ff d7 80 b6 90 01 05 46 81 fe 00 6e 03 00 72 94 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}