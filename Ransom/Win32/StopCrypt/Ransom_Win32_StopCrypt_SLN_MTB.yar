
rule Ransom_Win32_StopCrypt_SLN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 74 24 90 01 01 03 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 33 54 24 90 01 01 8d 4c 24 90 01 01 89 54 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}