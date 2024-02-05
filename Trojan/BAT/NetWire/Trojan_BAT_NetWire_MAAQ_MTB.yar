
rule Trojan_BAT_NetWire_MAAQ_MTB{
	meta:
		description = "Trojan:BAT/NetWire.MAAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 11 08 16 32 10 08 11 08 1f 27 58 1f 4e 5d 6f 90 01 01 00 00 0a 2b 05 11 04 11 05 93 9d 11 05 17 58 13 05 11 05 11 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}