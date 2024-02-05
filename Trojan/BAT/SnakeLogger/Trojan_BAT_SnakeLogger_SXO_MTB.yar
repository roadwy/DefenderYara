
rule Trojan_BAT_SnakeLogger_SXO_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.SXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 72 90 01 03 70 28 90 01 03 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}