
rule Ransom_Win32_StopCrypt_MZB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8b 4c 24 08 31 08 c2 90 02 02 8b 44 24 04 8b 4c 24 08 01 08 c2 90 02 02 8b 44 24 08 8b 4c 24 04 c1 e0 90 02 01 89 01 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}