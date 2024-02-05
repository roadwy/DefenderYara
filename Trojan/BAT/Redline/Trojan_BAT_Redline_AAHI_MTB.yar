
rule Trojan_BAT_Redline_AAHI_MTB{
	meta:
		description = "Trojan:BAT/Redline.AAHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 1f 00 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 17 58 06 8e 69 5d 0d 00 11 04 17 58 13 04 11 04 02 8e 69 18 59 fe 04 13 05 11 05 2d d2 } //00 00 
	condition:
		any of ($a_*)
 
}