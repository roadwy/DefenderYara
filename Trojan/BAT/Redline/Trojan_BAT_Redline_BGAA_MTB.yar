
rule Trojan_BAT_Redline_BGAA_MTB{
	meta:
		description = "Trojan:BAT/Redline.BGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 00 11 08 91 11 00 11 03 91 58 20 00 01 00 00 5d 13 07 } //02 00 
		$a_03_1 = {02 11 05 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 00 11 07 91 61 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}