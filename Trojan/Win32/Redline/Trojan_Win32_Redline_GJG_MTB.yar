
rule Trojan_Win32_Redline_GJG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 d7 0f b6 4d d7 8b 45 d8 33 d2 f7 75 10 0f b6 92 90 01 04 33 ca 88 4d df c7 45 90 01 05 8b 45 08 03 45 d8 8a 08 88 4d d6 8a 55 d6 88 55 d5 0f b6 45 df 8b 4d 08 03 4d d8 0f b6 11 03 d0 8b 45 08 03 45 d8 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}