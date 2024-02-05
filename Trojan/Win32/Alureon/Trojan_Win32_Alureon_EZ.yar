
rule Trojan_Win32_Alureon_EZ{
	meta:
		description = "Trojan:Win32/Alureon.EZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 00 20 00 00 66 09 46 16 8d 45 90 01 01 50 90 00 } //01 00 
		$a_01_1 = {74 4c 0f b7 48 14 0f b7 78 06 8d 74 01 18 } //01 00 
		$a_01_2 = {74 49 8d 45 fc 50 6a 05 6a 01 ff 75 08 ff 15 } //01 00 
		$a_01_3 = {05 22 22 22 22 50 b8 11 11 11 11 ff d0 33 c0 50 b8 33 33 33 33 ff d0 } //01 00 
		$a_01_4 = {8b 40 28 03 45 08 68 42 50 57 46 } //00 00 
	condition:
		any of ($a_*)
 
}