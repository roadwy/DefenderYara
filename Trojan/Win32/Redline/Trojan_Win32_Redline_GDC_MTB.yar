
rule Trojan_Win32_Redline_GDC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 4d d7 8b 45 d8 33 d2 be 90 01 04 f7 f6 0f b6 92 90 01 04 33 ca 88 4d df 8b 45 d8 8a 88 90 01 04 88 4d d6 0f b6 55 df 8b 45 d8 0f b6 88 90 01 04 03 ca 8b 55 d8 88 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}