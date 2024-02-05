
rule Trojan_Win32_Redline_GJF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 dc 8a 02 88 45 db 0f b6 4d db 8b 45 dc 33 d2 f7 75 10 0f b6 92 90 01 04 33 ca 88 4d e3 8b 45 08 03 45 dc 8a 08 88 4d da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}