
rule Trojan_Win32_Hala_B{
	meta:
		description = "Trojan:Win32/Hala.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 65 e8 33 f6 89 75 e4 56 56 6a 03 56 56 68 00 00 00 80 } //01 00 
		$a_01_1 = {5c 47 6f 6f 67 6c 65 00 53 6f 66 74 77 61 72 65 } //01 00  䝜潯汧e潓瑦慷敲
		$a_01_2 = {67 6f 6e 72 61 6a 61 2e 65 78 65 00 00 6d 68 63 } //01 00 
		$a_01_3 = {63 61 62 61 6c 2e 65 78 65 00 00 00 63 61 62 } //00 00 
	condition:
		any of ($a_*)
 
}