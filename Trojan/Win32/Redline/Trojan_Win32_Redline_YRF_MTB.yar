
rule Trojan_Win32_Redline_YRF_MTB{
	meta:
		description = "Trojan:Win32/Redline.YRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b 55 08 0f be 04 0a 8b 4d 90 01 01 03 4d 90 01 01 0f be 11 33 c2 88 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 08 88 4d 90 01 01 0f be 55 90 01 01 0f be 45 90 01 01 03 d0 8b 4d 90 01 01 03 4d 90 01 01 88 11 0f be 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}