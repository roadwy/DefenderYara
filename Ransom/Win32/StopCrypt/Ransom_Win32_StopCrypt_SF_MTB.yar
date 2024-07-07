
rule Ransom_Win32_StopCrypt_SF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 28 8b 44 24 90 01 01 33 c1 2b f0 ba 90 01 04 8d 4c 24 90 01 01 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}