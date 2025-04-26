
rule Ransom_Win32_CrysisCrypt_SN_MTB{
	meta:
		description = "Ransom:Win32/CrysisCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 85 ff 76 ?? 33 c9 89 7c 24 ?? 8b d7 0f af 54 24 ?? 89 54 24 ?? 8b 54 24 ?? 3b 4c 24 ?? 76 ?? 29 54 24 ?? eb 04 01 54 24 ?? 03 4c 24 ?? ff 4c 24 ?? 75 ?? 8a 4c 24 ?? 32 c8 8b 84 24 ?? 00 00 00 01 44 24 ?? 8b 44 24 ?? ff 44 24 ?? 01 44 24 ?? 88 0e 8d 74 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 3b 48 04 0f 82 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}