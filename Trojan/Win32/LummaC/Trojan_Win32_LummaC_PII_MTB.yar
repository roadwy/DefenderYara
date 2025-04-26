
rule Trojan_Win32_LummaC_PII_MTB{
	meta:
		description = "Trojan:Win32/LummaC.PII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 05 8d 0c 18 89 55 fc 8b 45 e8 01 45 fc 8b c3 c1 e0 ?? 03 45 e0 33 45 fc 33 c1 2b f8 89 7d f0 8b 45 d8 29 45 f8 83 6d ?? 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}