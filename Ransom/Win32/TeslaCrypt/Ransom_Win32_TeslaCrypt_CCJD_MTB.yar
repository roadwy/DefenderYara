
rule Ransom_Win32_TeslaCrypt_CCJD_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.CCJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 38 21 c0 8b 4c 24 3c 21 c9 8b 94 24 e8 00 00 00 81 f2 4c 17 00 00 8b 74 24 54 01 d6 89 8c 24 f8 00 00 00 89 84 24 fc 00 00 00 89 74 24 54 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}