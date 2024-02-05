
rule Trojan_Win32_Redline_MVK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ca 88 4d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 08 88 4d 90 01 01 0f b6 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 0f b6 08 03 ca 8b 55 90 01 01 03 55 90 01 01 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}