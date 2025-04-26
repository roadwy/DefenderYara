
rule Ransom_Linux_YouRans_A_MTB{
	meta:
		description = "Ransom:Linux/YouRans.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //1 main.encrypt
		$a_01_1 = {6d 61 69 6e 2e 64 6f 77 6e 6c 6f 61 64 52 65 61 64 6d 65 } //1 main.downloadReadme
		$a_01_2 = {59 6f 75 72 52 61 6e 73 6f 6d } //1 YourRansom
		$a_01_3 = {73 61 76 65 4b 65 79 } //1 saveKey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}