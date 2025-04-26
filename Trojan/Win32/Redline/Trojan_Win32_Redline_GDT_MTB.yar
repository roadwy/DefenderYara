
rule Trojan_Win32_Redline_GDT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e0 03 b9 ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 9e ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 08 8b 49 04 8b 4c 01 30 8b 49 04 89 8d ?? ?? ?? ?? 8b 11 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GDT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ea 6a 0e 07 c7 45 ?? be 0f d6 65 c7 45 ?? fe 8c 7d 37 c7 45 ?? ee b1 e9 23 c7 45 ?? e1 02 5b 54 c7 45 ?? 29 9f b2 1f c7 45 ?? 81 1a 44 62 c7 45 ?? 8f 1e cb 6e c7 45 ?? cc af 7a 55 c7 45 ?? 53 72 3b 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}