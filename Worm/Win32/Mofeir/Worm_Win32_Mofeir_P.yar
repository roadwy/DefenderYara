
rule Worm_Win32_Mofeir_P{
	meta:
		description = "Worm:Win32/Mofeir.P,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {32 c0 f6 44 24 04 01 75 0a d1 6c 24 04 fe c0 3c 1a 7c ef 83 c0 41 } //02 00 
		$a_03_1 = {88 45 fc 8d 45 fc 50 ff 15 90 01 04 83 f8 02 75 0b 90 00 } //02 00 
		$a_01_2 = {8b 4c 24 04 32 c0 f6 c1 01 75 08 d1 e9 fe c0 3c 1a 7c f3 83 c0 41 } //02 00 
		$a_03_3 = {88 44 24 18 ff d7 83 f8 02 a1 90 01 04 75 23 90 00 } //01 00 
		$a_01_4 = {5b 41 75 74 6f 52 75 6e 5d } //fb ff 
		$a_01_5 = {61 72 75 6e 75 73 62 2e 68 6c 70 } //00 00 
	condition:
		any of ($a_*)
 
}