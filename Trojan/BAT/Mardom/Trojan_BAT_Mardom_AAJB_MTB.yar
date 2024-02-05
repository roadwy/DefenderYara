
rule Trojan_BAT_Mardom_AAJB_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AAJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 01 00 00 0a 02 08 1e 58 1d 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 b7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}