
rule Trojan_Win32_Redline_GEW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 6b c0 90 01 01 99 be 90 01 04 f7 fe 83 e0 90 01 01 33 c8 88 4d 90 01 01 0f be 4d 90 01 01 0f be 55 90 01 01 03 ca 8b 45 90 01 01 03 45 90 01 01 88 08 0f be 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f be 02 2b c1 8b 4d 0c 03 4d 90 01 01 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}