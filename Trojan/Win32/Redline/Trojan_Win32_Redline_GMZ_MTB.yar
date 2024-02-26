
rule Trojan_Win32_Redline_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 80 34 03 90 01 01 ff d7 6a 00 ff d6 8b 44 24 90 01 01 6a 00 6a 00 80 34 03 90 01 01 ff d7 6a 00 ff d6 8b 44 24 90 01 01 6a 00 6a 00 80 04 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GMZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b c1 88 45 90 01 01 0f b6 55 90 01 01 03 55 90 01 01 88 55 90 01 01 0f b6 45 90 01 01 f7 d8 88 45 90 01 01 0f b6 4d 90 01 01 c1 f9 90 01 01 0f b6 55 90 01 01 c1 e2 90 01 01 0b ca 88 4d 90 01 01 0f b6 45 90 01 01 03 45 90 01 01 88 45 90 01 01 8b 4d 90 01 01 8a 55 90 01 01 88 54 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}