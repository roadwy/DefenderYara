
rule Trojan_Win32_Adialer_OO{
	meta:
		description = "Trojan:Win32/Adialer.OO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 31 39 34 2e 31 37 38 2e 31 31 32 2e 32 30 32 } //01 00 
		$a_02_1 = {85 c0 75 27 56 55 57 e8 90 01 04 83 3e 00 75 0a c7 05 90 01 03 00 01 00 00 00 68 90 01 03 00 ff d3 a1 90 01 02 40 00 85 c0 74 d9 90 00 } //01 00 
		$a_02_2 = {00 85 c0 74 d9 6a 24 68 90 01 03 00 68 90 01 03 00 6a 00 c7 05 90 01 04 00 00 00 00 ff 15 90 01 04 83 f8 07 75 11 c7 05 90 01 04 01 00 00 00 bd 01 00 00 00 eb 21 a1 90 01 03 00 bd 01 00 00 00 48 a3 90 01 03 00 eb 0f 8b 06 50 e8 90 01 04 68 d0 07 00 00 ff d3 90 00 } //01 00 
		$a_02_3 = {00 00 ff d3 83 3d 90 01 04 06 7c 06 89 90 01 03 40 00 8b 74 24 14 a1 90 01 03 00 83 c6 04 85 c0 89 90 00 } //01 00 
		$a_00_4 = {74 24 14 0f 84 a8 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}