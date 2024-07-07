
rule Ransom_Win32_StopCrypt_SAC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 89 1d 90 01 04 8b 45 90 01 01 29 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}