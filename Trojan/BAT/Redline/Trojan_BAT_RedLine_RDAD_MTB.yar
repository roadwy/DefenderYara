
rule Trojan_BAT_RedLine_RDAD_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6b 6d 6d 68 72 6d 63 6b 41 69 66 72 } //02 00 
		$a_03_1 = {03 08 03 8e 69 5d 7e 90 01 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 04 03 08 19 58 18 59 03 8e 69 5d 91 59 20 03 01 00 00 58 18 59 17 59 20 00 01 00 00 5d d2 9c 08 17 58 1a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}