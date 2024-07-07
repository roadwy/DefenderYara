
rule Ransom_Win32_StopCrypt_SG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 90 01 01 c7 05 90 01 08 31 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 05 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 c1 e0 90 01 01 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}