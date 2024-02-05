
rule Trojan_Win32_Clishmic_A{
	meta:
		description = "Trojan:Win32/Clishmic.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 4d 6f 72 70 68 43 6c 00 } //01 00 
		$a_01_1 = {43 6c 69 63 6b 65 72 20 68 69 64 64 65 6e 20 77 69 6e 64 6f 77 00 } //01 00 
		$a_01_2 = {4d 61 78 2d 46 6f 72 77 61 72 64 73 3a 20 39 39 39 00 } //01 00 
		$a_01_3 = {73 65 74 74 69 6e 67 73 2f 30 31 2e 74 78 74 00 } //01 00 
		$a_01_4 = {6b 65 79 73 2f 71 75 65 72 69 65 73 2e 74 78 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}