
rule Ransom_Win32_Tescrypt_NC_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {61 62 61 63 69 73 74 61 62 61 63 6b 61 62 61 63 6c 69 61 62 61 63 6f 74 61 62 61 63 75 73 61 62 61 63 75 73 65 73 } //3 abacistabackabacliabacotabacusabacuses
		$a_81_1 = {6e 20 69 66 20 79 6f 75 20 6c 69 6b 65 } //2 n if you like
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2) >=5
 
}