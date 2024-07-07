
rule Ransom_MSIL_Scott_DA_MTB{
	meta:
		description = "Ransom:MSIL/Scott.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 63 6f 74 74 20 72 61 73 6f 6d } //1 scott rasom
		$a_81_1 = {69 20 77 69 6c 6c 20 77 69 6c 6c 20 67 69 76 65 20 79 6f 75 20 74 68 65 20 70 61 73 73 77 6f 72 64 } //1 i will will give you the password
		$a_81_2 = {69 20 77 69 6c 6c 20 64 65 73 74 72 6f 79 20 74 68 65 20 6b 65 79 20 61 6e 64 20 79 6f 75 20 77 69 6c 6c 20 6e 65 76 65 72 20 67 65 74 20 69 74 20 67 6f 6f 64 20 6c 75 63 6b } //1 i will destroy the key and you will never get it good luck
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}