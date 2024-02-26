
rule Trojan_BAT_SnakeKeylogger_SPFF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {5d 91 59 20 90 01 03 00 58 13 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}