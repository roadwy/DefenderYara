
rule Trojan_Win32_Redline_NII_MTB{
	meta:
		description = "Trojan:Win32/Redline.NII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 45 d0 89 45 f4 8b 45 e4 31 45 90 01 01 8b 45 fc 33 45 f4 2b f8 89 45 fc 89 7d e8 8b 45 cc 29 45 f8 ff 4d e0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}