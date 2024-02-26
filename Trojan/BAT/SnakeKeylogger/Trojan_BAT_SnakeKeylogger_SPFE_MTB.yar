
rule Trojan_BAT_SnakeKeylogger_SPFE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {5d 59 d2 9c 00 11 05 17 58 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}