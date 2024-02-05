
rule Trojan_Win32_Alureon_DE{
	meta:
		description = "Trojan:Win32/Alureon.DE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 57 c6 45 90 01 01 43 c6 45 90 01 01 63 c6 45 90 01 01 5a c6 45 90 01 01 65 c6 45 90 01 01 72 c6 45 90 01 01 6f c6 45 90 01 01 44 c6 45 90 01 01 61 c6 45 90 01 01 74 c6 45 90 01 01 61 c6 45 90 01 01 00 90 00 } //01 00 
		$a_03_1 = {6a 6f 58 6a 74 66 89 45 90 01 01 58 6a 67 90 00 } //01 00 
		$a_01_2 = {50 b8 a9 32 8c 7a ff d0 } //01 00 
		$a_03_3 = {8b 43 08 01 45 08 81 73 0c 90 01 04 8b 5b 0c 8b 46 2c 03 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}