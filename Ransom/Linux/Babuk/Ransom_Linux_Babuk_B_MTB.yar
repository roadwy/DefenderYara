
rule Ransom_Linux_Babuk_B_MTB{
	meta:
		description = "Ransom:Linux/Babuk.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {55 73 61 67 65 3a 20 25 73 [0-07] 2f 74 6f 2f 62 65 2f 65 6e 63 [0-02] 79 70 74 65 64 } //1
		$a_01_1 = {2e 76 6d 64 6b } //1 .vmdk
		$a_01_2 = {2e 76 73 77 70 } //1 .vswp
		$a_01_3 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 3a } //1 Encrypted files:
		$a_01_4 = {53 6b 69 70 70 65 64 20 66 69 6c 65 73 3a } //1 Skipped files:
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}