
rule Ransom_Win32_StopCrypt_CRTD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CRTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b ce c1 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}