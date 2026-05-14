
rule Ransom_Win32_Kraken_E_ldr{
	meta:
		description = "Ransom:Win32/Kraken.E!ldr,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 61 64 20 70 61 74 68 } //1 Bad path
		$a_01_1 = {42 61 64 20 70 61 72 61 6d 73 2e 2e 2e } //1 Bad params...
		$a_01_2 = {4d 79 20 70 61 74 68 3a 20 } //1 My path: 
		$a_01_3 = {4c 65 74 73 27 67 6f 2e 2e 2e } //1 Lets'go...
		$a_01_4 = {62 61 64 20 6e 65 77 20 66 69 6c 65 } //1 bad new file
		$a_01_5 = {62 61 64 20 6f 70 65 6e 20 27 25 73 27 } //1 bad open '%s'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}