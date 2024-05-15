
rule Trojan_BAT_Remcos_JWAA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.JWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 0b 11 0c 91 07 11 07 17 58 11 06 5d 91 13 0d 08 11 07 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}