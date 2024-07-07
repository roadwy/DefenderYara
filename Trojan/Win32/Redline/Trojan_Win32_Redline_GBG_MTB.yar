
rule Trojan_Win32_Redline_GBG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 13 6b c0 90 01 01 8b 55 90 01 01 30 04 0a 8d 41 90 01 01 31 d2 f7 f7 c1 ea 90 01 01 0f b6 04 13 89 da 6b c0 90 01 01 8b 7d 90 01 01 30 44 0f 90 01 01 8b 45 90 01 01 83 c1 90 01 01 39 4e 90 01 01 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}