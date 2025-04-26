
rule Ransom_Win32_StopCrypt_SLB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 f8 89 45 ?? 8b 55 ?? 8b 4d ?? d3 e2 8b 45 ?? 33 c2 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 0b d1 89 55 ?? 83 7d } //1
		$a_03_1 = {2b c8 89 4d ?? 8b 55 ?? 6b d2 ?? 8b 45 ?? 0b c2 89 45 ?? 8b 4d ?? 83 f1 ?? 8b 55 ?? 33 d1 89 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}