
rule Trojan_Win32_Redline_MDZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 0a 8b 45 90 01 01 99 be 90 01 04 f7 fe 8b 45 90 01 01 0f be 14 10 6b d2 90 01 01 83 e2 90 01 01 33 ca 88 4d 90 01 01 0f be 45 90 01 01 0f be 4d 90 01 01 03 c1 8b 55 90 01 01 03 55 90 01 01 88 02 0f be 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 0f be 11 2b d0 8b 45 90 01 01 03 45 90 01 01 88 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}