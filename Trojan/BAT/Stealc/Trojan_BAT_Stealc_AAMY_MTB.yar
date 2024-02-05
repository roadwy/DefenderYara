
rule Trojan_BAT_Stealc_AAMY_MTB{
	meta:
		description = "Trojan:BAT/Stealc.AAMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 7e 90 01 01 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 01 00 00 06 02 08 1b 58 1a 59 02 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}