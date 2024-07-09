
rule Trojan_Win32_Zenpak_DG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d4 88 1c 31 8b 4d f0 39 cf 8b 4d ?? 89 55 ?? 89 4d ?? 89 7d ?? 0f 85 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}