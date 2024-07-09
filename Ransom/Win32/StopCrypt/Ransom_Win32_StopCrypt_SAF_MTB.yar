
rule Ransom_Win32_StopCrypt_SAF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 c5 89 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 ?? 18 89 44 ?? 2c 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8d 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}