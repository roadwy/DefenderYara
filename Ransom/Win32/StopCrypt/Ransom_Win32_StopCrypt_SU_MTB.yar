
rule Ransom_Win32_StopCrypt_SU_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 89 75 90 01 01 8b 45 90 01 01 01 45 90 01 01 2b 7d 90 01 01 ff 4d 90 01 01 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}