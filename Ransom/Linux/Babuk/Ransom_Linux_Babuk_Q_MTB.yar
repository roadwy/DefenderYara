
rule Ransom_Linux_Babuk_Q_MTB{
	meta:
		description = "Ransom:Linux/Babuk.Q!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 main.encrypt_file
		$a_01_1 = {45 6e 64 70 6f 69 6e 74 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Endpoint Ransomware
		$a_01_2 = {52 73 57 61 72 65 2f 6e 61 73 5f 32 2f 65 6e 63 2f 6d 61 69 6e 2e 67 6f } //1 RsWare/nas_2/enc/main.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}