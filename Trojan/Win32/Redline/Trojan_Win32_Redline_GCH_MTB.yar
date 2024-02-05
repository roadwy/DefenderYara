
rule Trojan_Win32_Redline_GCH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 33 d2 be 90 01 04 f7 f6 0f b6 92 90 01 04 33 ca 88 4d 90 01 01 8b 45 90 01 01 8a 88 90 01 04 88 4d 90 01 01 0f b6 55 90 01 01 8b 45 90 01 01 0f b6 88 90 01 04 03 ca 8b 55 d8 88 8a 90 01 04 8a 45 90 01 01 88 45 90 01 01 0f b6 4d 90 01 01 8b 55 90 01 01 0f b6 82 90 01 04 2b c1 8b 4d d8 88 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}