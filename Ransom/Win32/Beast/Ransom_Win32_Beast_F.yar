
rule Ransom_Win32_Beast_F{
	meta:
		description = "Ransom:Win32/Beast.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 54 06 04 8b 0e 02 c8 32 ca 88 4c 06 04 40 83 f8 1b 72 ?? 5f c6 46 1f 00 8d 46 04 5e c3 } //1
		$a_03_1 = {42 45 41 53 54 20 7c 20 54 79 70 65 20 36 36 36 20 77 68 69 6c 65 20 68 6f 6c 64 69 6e 67 20 41 4c 54 2b 43 54 ?? 4c 20 74 6f 20 68 69 64 65 2f 73 68 6f 77 20 74 68 69 73 20 77 69 6e 64 6f 77 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}