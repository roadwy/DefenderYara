
rule Trojan_Win32_Alureon_GD{
	meta:
		description = "Trojan:Win32/Alureon.GD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 75 61 63 36 34 6f 6b 00 } //01 00 
		$a_03_1 = {50 6a 02 53 e8 90 01 04 ff d6 90 05 02 02 ff d6 3d 5a 04 00 00 74 0b ff d6 83 f8 7f 74 04 90 00 } //01 00 
		$a_03_2 = {85 c0 74 0f 33 c0 81 7d 90 01 01 55 05 00 00 0f 94 c0 89 45 90 01 01 ff 75 90 01 01 ff d6 90 00 } //01 00 
		$a_03_3 = {6a 04 68 00 30 00 00 68 06 01 00 00 56 ff 75 10 ff 15 90 01 04 8b d8 3b de 0f 84 90 01 04 8b 45 0c 8d 50 02 66 8b 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}