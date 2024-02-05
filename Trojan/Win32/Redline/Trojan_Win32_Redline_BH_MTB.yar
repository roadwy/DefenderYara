
rule Trojan_Win32_Redline_BH_MTB{
	meta:
		description = "Trojan:Win32/Redline.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 75 e8 0f b6 92 90 02 04 33 ca 88 4d ff 8b 45 f8 8a 88 90 02 04 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 90 02 04 03 ca 8b 55 f8 88 8a 90 02 04 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 f8 0f b6 82 90 02 04 2b c1 8b 4d f8 88 81 90 02 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}