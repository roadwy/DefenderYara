
rule Ransom_Win32_StopCrypt_SLN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 74 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 33 54 24 ?? 8d 4c 24 ?? 89 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}