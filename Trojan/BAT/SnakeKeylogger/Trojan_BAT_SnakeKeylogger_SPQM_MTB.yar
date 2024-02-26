
rule Trojan_BAT_SnakeKeylogger_SPQM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 6f 90 01 03 0a 05 03 02 8e 69 6f 90 01 03 0a 0a 06 28 90 01 03 0a 00 06 0b 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}