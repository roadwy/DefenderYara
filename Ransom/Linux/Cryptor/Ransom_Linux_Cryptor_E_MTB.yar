
rule Ransom_Linux_Cryptor_E_MTB{
	meta:
		description = "Ransom:Linux/Cryptor.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 73 61 76 65 43 75 72 72 50 49 44 } //1 main.saveCurrPID
		$a_01_1 = {6d 61 69 6e 2e 72 65 6d 6f 76 65 43 72 6f 6e } //1 main.removeCron
		$a_01_2 = {6d 61 69 6e 2e 63 68 65 63 6b 52 65 61 64 6d 65 45 78 69 73 74 73 } //1 main.checkReadmeExists
		$a_01_3 = {6d 61 69 6e 2e 77 72 69 74 65 6d 65 73 73 61 67 65 } //1 main.writemessage
		$a_01_4 = {2f 73 72 63 2f 72 63 74 5f 63 72 79 70 74 6f 72 5f 75 6e 69 76 65 72 73 61 6c 2f 6d 61 69 6e 2e 67 6f } //1 /src/rct_cryptor_universal/main.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}