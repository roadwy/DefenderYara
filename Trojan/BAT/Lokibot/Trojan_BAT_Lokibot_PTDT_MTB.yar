
rule Trojan_BAT_Lokibot_PTDT_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PTDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 af d0 c9 86 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 28 90 01 01 00 00 06 0a 06 28 90 01 01 00 00 06 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}