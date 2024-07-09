
rule Ransom_Win32_StopCrypt_SU_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 7d ?? ff 4d ?? 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}