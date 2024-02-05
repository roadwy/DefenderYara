
rule Trojan_BAT_DarkKomet_AAOX_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.AAOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {2b 40 2b 41 2b 42 08 91 06 08 06 8e b7 5d 91 61 9c 08 17 d6 16 2d d7 0c 1b 2c 09 } //00 00 
	condition:
		any of ($a_*)
 
}