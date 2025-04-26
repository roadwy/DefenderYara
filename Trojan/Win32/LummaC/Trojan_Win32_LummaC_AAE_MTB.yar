
rule Trojan_Win32_LummaC_AAE_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 03 8b 4d ?? 83 e9 ?? 89 06 83 6d ?? 01 89 13 89 4d ?? 75 ?? 89 16 89 03 8b 4f ?? 33 c8 89 0b 8b 07 33 c2 89 06 83 c6 ?? 8b 45 ?? 40 89 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}