
rule Ransom_Linux_Mario_A_MTB{
	meta:
		description = "Ransom:Linux/Mario.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 6d 61 72 69 6f } //1 .mario
		$a_01_1 = {52 61 6e 73 6f 6d 48 6f 75 73 65 } //1 RansomHouse
		$a_01_2 = {2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 } //1 /path/to/be/encrypted
		$a_01_3 = {48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //1 How To Restore Your Files.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}