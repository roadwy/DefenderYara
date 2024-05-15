
rule Trojan_BAT_SnakeKeylogger_SPBP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {5d 91 61 28 90 01 03 0a 07 11 90 01 01 17 58 07 8e 69 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}