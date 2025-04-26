
rule Ransom_MSIL_HiddenTear_DN_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_1 = {62 69 74 63 6f 69 6e } //1 bitcoin
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_3 = {68 69 64 64 65 6e 5f 74 65 61 72 } //1 hidden_tear
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}