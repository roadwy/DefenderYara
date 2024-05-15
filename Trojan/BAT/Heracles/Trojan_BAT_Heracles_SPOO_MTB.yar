
rule Trojan_BAT_Heracles_SPOO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 90 01 01 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f 28 90 01 03 0a 9c 08 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}