
rule Ransom_Linux_GoRansom_A_MTB{
	meta:
		description = "Ransom:Linux/GoRansom.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 72 61 6e 73 6f 6d 77 61 72 65 } //1 main.ransomware
		$a_01_1 = {45 6e 63 72 79 70 74 } //1 Encrypt
		$a_00_2 = {2e 64 65 63 72 79 70 74 } //1 .decrypt
		$a_01_3 = {6d 61 69 6e 2e 73 74 61 72 74 2e 66 75 6e 63 31 } //1 main.start.func1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}