
rule Trojan_Win32_Redline_GBG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 13 6b c0 ?? 8b 55 ?? 30 04 0a 8d 41 ?? 31 d2 f7 f7 c1 ea ?? 0f b6 04 13 89 da 6b c0 ?? 8b 7d ?? 30 44 0f ?? 8b 45 ?? 83 c1 ?? 39 4e ?? 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}