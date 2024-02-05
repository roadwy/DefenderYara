
rule Trojan_Win32_Redline_WDS_MTB{
	meta:
		description = "Trojan:Win32/Redline.WDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 88 45 d3 0f b6 4d 90 01 01 51 8d 4d 90 01 01 e8 90 01 04 0f b6 10 81 e2 a3 11 00 00 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}