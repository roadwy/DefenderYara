
rule Ransom_MSIL_BlackShades_A_bit{
	meta:
		description = "Ransom:MSIL/BlackShades.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6c 61 63 6b 53 68 61 64 65 73 20 43 72 79 70 74 65 72 } //1 BlackShades Crypter
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 70 72 6f 74 65 63 74 65 64 20 62 79 20 61 20 73 74 72 6f 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e } //1 Your files were protected by a strong encryption
		$a_01_2 = {42 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 63 63 6f 75 6e 74 } //1 Bitcoin to this account
		$a_01_3 = {54 68 65 20 69 6e 66 65 63 74 69 6f 6e 20 65 6e 63 72 79 70 74 73 20 65 76 65 72 79 74 68 69 6e 67 } //1 The infection encrypts everything
		$a_01_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}