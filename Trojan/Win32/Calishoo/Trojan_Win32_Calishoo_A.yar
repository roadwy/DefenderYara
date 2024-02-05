
rule Trojan_Win32_Calishoo_A{
	meta:
		description = "Trojan:Win32/Calishoo.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 6e 67 65 6c 6c 65 6e 64 69 6b 74 65 6e 20 73 6f 6e 72 61 20 74 65 6b 72 61 72 20 63 61 6c 69 73 74 69 72 69 6c 64 69 21 } //01 00 
		$a_01_1 = {2f 77 2f 31 73 74 75 70 6c 6f 61 64 2e 70 68 70 } //02 00 
		$a_01_2 = {2f 56 20 73 79 73 63 68 65 63 6b 20 2f 44 20 22 5c 22 } //02 00 
		$a_01_3 = {63 6f 6e 74 65 75 64 6f 3d } //02 00 
		$a_03_4 = {53 69 66 72 65 6c 65 72 69 90 09 04 00 4d 73 6e 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}