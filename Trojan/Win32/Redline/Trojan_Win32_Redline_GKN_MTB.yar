
rule Trojan_Win32_Redline_GKN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8d 3c 13 89 45 fc 8b 45 d4 01 45 fc 8b 45 fc 33 c7 31 45 f8 89 35 90 01 04 8b 45 f4 89 45 f0 8b 45 f8 29 45 f0 8b 45 f0 89 45 f4 81 c3 47 86 c8 61 ff 4d e4 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}