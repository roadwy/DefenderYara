
rule Ransom_Win32_TeslaCrypt_ERL_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.ERL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 8b 94 24 ba 00 00 00 8a 5c 24 2f 88 9c 24 b9 00 00 00 66 2b 8c 24 ba 00 00 00 66 29 d0 66 89 84 24 b2 00 00 00 66 39 8c 24 b2 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}