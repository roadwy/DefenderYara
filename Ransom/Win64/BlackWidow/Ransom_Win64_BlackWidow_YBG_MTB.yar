
rule Ransom_Win64_BlackWidow_YBG_MTB{
	meta:
		description = "Ransom:Win64/BlackWidow.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 4c 41 43 4b 20 57 49 44 4f 57 } //1 BLACK WIDOW
		$a_01_1 = {73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 servers are encrypted
		$a_01_2 = {62 69 74 63 6f 69 6e } //1 bitcoin
		$a_01_3 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 } //1 You have to pay
		$a_01_4 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //1 Decryption Key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}