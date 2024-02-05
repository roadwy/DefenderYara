
rule Trojan_Win32_Alureon_EC{
	meta:
		description = "Trojan:Win32/Alureon.EC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 c7 47 16 02 21 53 89 75 f8 89 75 fc ff 15 } //01 00 
		$a_03_1 = {8a 4e 26 02 c8 30 88 90 01 04 40 83 f8 90 01 01 7c ef 90 00 } //01 00 
		$a_01_2 = {68 90 01 00 00 8d 85 2c fd ff ff 50 8d 85 c0 fe ff ff 50 e8 } //01 00 
		$a_01_3 = {76 15 8b 44 24 04 8a d1 02 54 24 0c 03 c1 30 10 41 } //01 00 
		$a_03_4 = {8a c8 80 c1 66 30 8c 05 90 01 04 40 3b c7 72 ef 90 00 } //01 00 
		$a_01_5 = {c6 45 f8 e9 ab 8b 45 08 89 45 18 ff 75 18 e8 } //01 00 
		$a_01_6 = {3f 69 3d 25 73 26 61 3d 25 64 26 66 3d 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}