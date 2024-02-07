
rule Trojan_Win32_Congrim_gen_A{
	meta:
		description = "Trojan:Win32/Congrim.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 38 3a cb 75 0a c6 84 14 90 01 04 2c eb 07 90 00 } //01 00 
		$a_01_1 = {50 75 74 46 69 6c 65 00 } //01 00  畐䙴汩e
		$a_01_2 = {8b 74 24 3c 56 ff d3 83 c4 28 85 c0 5f 5d 74 14 } //01 00 
		$a_01_3 = {8a 5e 01 0a 59 01 8a 48 01 40 0a cb 42 81 ff 00 01 00 00 88 08 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}