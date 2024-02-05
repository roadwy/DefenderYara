
rule Trojan_Win32_Pirpi_B{
	meta:
		description = "Trojan:Win32/Pirpi.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 03 ff 55 e8 c6 45 90 01 01 6b c6 45 90 01 01 65 c6 45 90 01 01 72 c6 45 90 01 01 6e 90 00 } //02 00 
		$a_03_1 = {85 d2 7e 1d 8a 84 90 01 05 3c 7a 7f 0d 3c 61 7c 09 90 00 } //02 00 
		$a_03_2 = {03 c8 05 f5 3f 00 00 a3 90 01 04 89 0d 90 01 04 89 0d 90 01 04 b8 01 00 00 00 90 00 } //02 00 
		$a_01_3 = {73 70 30 00 55 8d 6c 24 c8 81 ec 68 01 00 00 a1 c8 e1 ca 76 } //01 00 
		$a_01_4 = {6e 74 6c 6d 64 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_01_5 = {6d 73 6e 74 6c 6d 2e 74 6d 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}