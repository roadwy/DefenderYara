
rule Trojan_Win32_Redline_CAV_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 4d d3 51 8d 4d e4 e8 90 02 04 0f b6 10 6b d2 90 01 01 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}