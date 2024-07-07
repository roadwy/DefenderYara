
rule Ransom_MSIL_Blacksun_DB_MTB{
	meta:
		description = "Ransom:MSIL/Blacksun.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4f 6f 70 73 2c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Oops, your important files are encrypted
		$a_81_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin delete shadows /All /Quiet
		$a_81_2 = {44 65 63 72 79 70 74 69 6f 6e 2e 6b 65 79 } //1 Decryption.key
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_4 = {2e 62 6c 61 63 6b 73 75 6e } //1 .blacksun
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}