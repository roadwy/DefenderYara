
rule Trojan_BAT_Lokibot_HTAA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.HTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {26 dd 00 00 00 00 11 04 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}