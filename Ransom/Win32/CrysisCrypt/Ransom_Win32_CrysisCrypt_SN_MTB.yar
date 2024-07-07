
rule Ransom_Win32_CrysisCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/CrysisCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 85 ff 76 90 01 01 33 c9 89 7c 24 90 01 01 8b d7 0f af 54 24 90 01 01 89 54 24 90 01 01 8b 54 24 90 01 01 3b 4c 24 90 01 01 76 90 01 01 29 54 24 90 01 01 eb 04 01 54 24 90 01 01 03 4c 24 90 01 01 ff 4c 24 90 01 01 75 90 01 01 8a 4c 24 90 01 01 32 c8 8b 84 24 90 01 01 00 00 00 01 44 24 90 01 01 8b 44 24 90 01 01 ff 44 24 90 01 01 01 44 24 90 01 01 88 0e 8d 74 24 90 01 01 e8 90 01 04 8b 4c 24 90 01 01 3b 48 04 0f 82 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}