
rule Ransom_Win32_StopCrypt_SLO_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 e2 89 5c 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c7 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 1d ?? ?? ?? ?? 33 d1 8d 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}