
rule Trojan_Win32_Zenpak_DE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 31 8b 75 ?? 01 f1 81 e1 [0-04] 8b 75 ?? 8b 5d ?? 8a 1c 1e 8b 75 ?? 32 1c 0e 8b 4d ?? 8b 75 ?? 88 1c 31 8b 4d ?? 39 cf 8b 4d ?? 89 55 ?? 89 4d ?? 89 7d ?? 0f 84 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}