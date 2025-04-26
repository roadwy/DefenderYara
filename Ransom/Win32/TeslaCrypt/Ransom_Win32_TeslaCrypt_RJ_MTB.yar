
rule Ransom_Win32_TeslaCrypt_RJ_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 19 00 00 00 2b cb 69 c9 8a 00 00 00 b8 1f 85 eb 51 f7 e1 8b f2 c1 ee 05 46 56 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}