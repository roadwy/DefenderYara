
rule Trojan_BAT_SnakeKeylogger_SPAQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 08 11 04 16 73 55 02 00 0a 0d 09 07 6f 90 01 03 0a 07 6f 90 01 03 0a 13 05 de 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}