
rule Trojan_BAT_SnakeKeylogger_ABRJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 06 72 df 06 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 07 06 72 e5 06 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 07 06 72 eb 06 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 07 06 72 f1 06 00 70 6f 90 01 03 0a 74 90 01 03 1b 6f 90 01 03 0a 00 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}