
rule Trojan_BAT_Seraph_AAVY_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {94 58 20 00 01 00 00 5d 7d 90 01 01 00 00 0a 20 08 00 00 00 38 90 01 01 fd ff ff 02 02 7b 90 01 01 00 00 0a 17 58 7d 90 01 01 00 00 0a 20 01 00 00 00 7e 90 01 01 00 00 04 3a 90 01 01 fd ff ff 26 38 90 01 01 fd ff ff 02 7b 90 01 01 00 00 0a 02 7b 90 01 01 00 00 0a 03 02 7b 90 01 01 00 00 0a 91 02 7b 90 01 01 00 00 0a 61 d2 9c 20 09 00 00 00 7e 90 01 01 00 00 04 39 90 01 01 fd ff ff 26 38 90 01 01 fd ff ff 02 03 8e 69 8d 90 01 01 00 00 01 17 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}