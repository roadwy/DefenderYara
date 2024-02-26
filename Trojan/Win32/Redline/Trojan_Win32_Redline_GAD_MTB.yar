
rule Trojan_Win32_Redline_GAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff 80 34 2f 90 01 01 83 c4 08 6a 00 6a 00 ff d6 68 90 01 04 68 90 01 04 e8 90 01 04 80 04 2f 90 01 01 83 c4 08 6a 00 6a 00 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GAD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 08 88 4d ef 0f b6 4d ef 8b 45 f0 33 d2 f7 75 10 0f b6 92 90 01 04 33 ca 88 4d fb 8b 45 0c 03 45 f0 8a 08 88 4d ee 0f b6 55 fb 8b 45 0c 03 45 f0 0f b6 08 03 ca 8b 55 0c 03 55 f0 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}