
rule Trojan_Win32_SharpPanda_PA_MTB{
	meta:
		description = "Trojan:Win32/SharpPanda.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 8a 04 1f 88 04 1e 88 0c 1f 0f b6 04 1e 8b 4d ?? 03 c2 8b 55 ?? 0f b6 c0 8a 04 18 30 04 11 41 89 4d ?? 3b 4d ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}