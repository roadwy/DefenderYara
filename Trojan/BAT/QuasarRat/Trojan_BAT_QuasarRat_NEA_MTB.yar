
rule Trojan_BAT_QuasarRat_NEA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 0f 00 00 06 0b 07 16 07 8e 69 28 23 00 00 0a 00 07 0c 2b 00 08 2a } //1
		$a_01_1 = {4c 00 6f 00 7a 00 70 00 75 00 75 00 63 00 64 00 70 00 65 00 } //1 Lozpuucdpe
		$a_01_2 = {45 00 6c 00 68 00 6f 00 78 00 78 00 7a 00 66 00 70 00 67 00 66 00 79 00 74 00 67 00 } //1 Elhoxxzfpgfytg
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}