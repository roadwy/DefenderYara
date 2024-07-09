
rule Trojan_Win32_QakbotPacker_AF_MTB{
	meta:
		description = "Trojan:Win32/QakbotPacker.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 66 3b ff 74 ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 3a c0 90 13 8b 45 ?? 03 45 ?? 88 08 90 13 8b 45 ?? 40 90 13 89 45 ?? 8b 45 ?? 3b 45 ?? 73 ?? 90 13 8b 45 ?? 03 45 ?? 0f b6 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}