
rule Trojan_Win32_Redline_BO_MTB{
	meta:
		description = "Trojan:Win32/Redline.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b f8 8b c7 c1 e8 05 c7 05 90 02 04 19 36 6b ff 89 45 0c 8b 45 e4 01 45 0c 83 65 08 00 8b c7 c1 e0 04 03 45 f0 8d 0c 3e 33 c1 33 45 0c 2b d8 8b 45 e8 01 45 08 2b 75 08 ff 4d fc 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_BO_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 d1 88 4d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 08 88 4d 90 01 01 0f b6 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 0f b6 08 90 00 } //01 00 
		$a_03_1 = {03 ca 8b 55 90 01 01 03 55 90 01 01 88 0a 8a 45 90 01 01 88 45 90 01 01 0f b6 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 2b c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}