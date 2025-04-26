
rule Ransom_MSIL_Fsysna_DA_MTB{
	meta:
		description = "Ransom:MSIL/Fsysna.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 43 6f 6d 70 75 74 65 72 20 48 61 73 20 42 65 65 6e 20 43 6f 6d 70 72 6f 6d 69 73 65 64 21 } //1 Your Computer Has Been Compromised!
		$a_81_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_81_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_3 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } //1 EncryptedKey
		$a_81_4 = {42 69 74 63 6f 69 6e 20 41 64 64 72 65 73 73 } //1 Bitcoin Address
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}