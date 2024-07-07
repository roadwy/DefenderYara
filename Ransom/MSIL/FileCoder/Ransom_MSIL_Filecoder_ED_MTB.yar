
rule Ransom_MSIL_Filecoder_ED_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {55 68 20 6f 68 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 Uh oh, your files are encrypted!
		$a_81_1 = {52 61 6e 73 6f 6d 5f 4e 6f 74 65 } //1 Ransom_Note
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } //1 DisableTaskmgr
		$a_81_3 = {54 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 70 72 6f 76 69 64 65 64 20 69 73 20 69 6e 63 6f 72 72 65 63 74 } //1 The decryption key provided is incorrect
		$a_81_4 = {44 65 63 72 79 70 74 65 64 21 } //1 Decrypted!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}