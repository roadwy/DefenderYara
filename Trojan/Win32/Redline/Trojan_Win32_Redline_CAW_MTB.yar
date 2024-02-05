
rule Trojan_Win32_Redline_CAW_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 90 02 04 0f b6 10 69 d2 90 02 04 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}