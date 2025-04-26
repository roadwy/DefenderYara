
rule Ransom_Linux_Akita_A_MTB{
	meta:
		description = "Ransom:Linux/Akita.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6b 69 74 61 43 72 79 70 74 } //1 AkitaCrypt
		$a_01_1 = {2e 2f 65 6e 63 72 79 70 74 20 5b 6b 65 79 5d } //1 ./encrypt [key]
		$a_01_2 = {2f 72 6f 6f 74 2f 64 65 63 72 79 70 74 2e 68 74 6d 6c } //1 /root/decrypt.html
		$a_01_3 = {67 65 74 6d 79 66 69 6c 65 73 62 61 63 6b 6e 6f 77 } //1 getmyfilesbacknow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}