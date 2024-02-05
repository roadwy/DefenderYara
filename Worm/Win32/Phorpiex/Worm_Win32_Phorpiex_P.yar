
rule Worm_Win32_Phorpiex_P{
	meta:
		description = "Worm:Win32/Phorpiex.P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 0a 00 00 00 f7 f9 52 56 68 90 01 04 56 90 03 02 04 ff d3 e8 90 01 04 83 c4 10 83 ef 01 75 90 01 01 5f c6 46 90 00 } //01 00 
		$a_03_1 = {80 38 00 74 90 01 01 50 8d 44 24 90 01 01 50 90 03 02 04 ff d7 e8 90 01 04 83 c4 08 85 c0 75 90 01 01 46 83 fe 03 72 90 00 } //01 00 
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}