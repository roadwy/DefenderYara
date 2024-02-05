
rule Trojan_Win32_Redline_MKA_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 90 01 01 8b 4d 90 01 01 0f be 04 11 6b c0 90 01 01 99 b9 90 01 04 f7 f9 6b c0 0c 99 83 e2 90 01 01 03 c2 c1 f8 90 01 01 6b c0 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 0a 33 c8 8b 55 90 01 01 03 55 90 01 01 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}