
rule Ransom_Linux_Biotech_A_MTB{
	meta:
		description = "Ransom:Linux/Biotech.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 6c 61 63 6b 5f 6c 65 74 74 65 72 2e 74 78 74 } //1 black_letter.txt
		$a_00_1 = {25 73 2e 62 69 6f 74 65 63 68 } //1 %s.biotech
		$a_00_2 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 encrypt_file
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}