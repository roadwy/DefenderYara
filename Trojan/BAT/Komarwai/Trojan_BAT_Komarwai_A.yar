
rule Trojan_BAT_Komarwai_A{
	meta:
		description = "Trojan:BAT/Komarwai.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {6b 00 6f 00 6d 00 61 00 72 00 67 00 61 00 6d 00 65 00 73 00 2e 00 72 00 75 00 2f 00 } //04 00 
		$a_03_1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 90 02 04 2d 00 73 00 20 00 2d 00 74 00 20 00 30 00 30 00 20 00 2d 00 66 00 90 00 } //02 00 
		$a_01_2 = {77 69 61 64 65 62 75 67 2e 65 78 65 } //01 00 
		$a_01_3 = {73 65 74 5f 6d 6f 75 73 65 48 6f 6f 6b } //01 00 
		$a_01_4 = {53 63 72 65 65 6e 73 68 6f 74 54 6f 43 6c 69 70 62 6f 61 72 64 } //01 00 
		$a_01_5 = {73 65 74 5f 47 65 74 44 72 69 76 65 73 } //00 00 
		$a_00_6 = {87 10 00 00 91 11 2a } //e8 3b 
	condition:
		any of ($a_*)
 
}