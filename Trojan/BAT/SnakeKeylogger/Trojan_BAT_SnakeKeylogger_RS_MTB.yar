
rule Trojan_BAT_SnakeKeylogger_RS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {08 07 11 09 9a 1f 10 28 68 00 00 0a 6f 69 00 00 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db } //00 00 
	condition:
		any of ($a_*)
 
}