
rule Trojan_BAT_MSILZilla_CCHZ_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 0a 11 0c 18 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 11 0c 18 58 13 0c 11 0c 11 0b 31 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}