
rule Trojan_Win32_Redline_CRIV_MTB{
	meta:
		description = "Trojan:Win32/Redline.CRIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 10 0f b6 92 80 56 45 00 33 ca 88 4d ff 8b 45 08 } //00 00 
	condition:
		any of ($a_*)
 
}