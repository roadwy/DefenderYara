
rule Trojan_BAT_Lokibot_KAB_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 6e 08 8e 69 6a 5d d4 91 58 11 90 01 01 09 95 58 20 ff 00 00 00 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}