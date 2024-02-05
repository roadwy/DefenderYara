
rule Trojan_BAT_Matanbuchus_AAMK_MTB{
	meta:
		description = "Trojan:BAT/Matanbuchus.AAMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 1a 58 4a 03 8e 69 5d 7e 90 01 02 00 04 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 90 01 02 00 06 03 06 1a 58 4a 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}