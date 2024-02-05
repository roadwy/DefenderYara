
rule Trojan_BAT_SnakeKeylogger_SPWR_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {2b 1e 11 17 6f 90 01 03 0a 13 3e 11 0d 11 3e 11 22 59 61 13 0d 11 22 19 11 0d 58 1e 63 59 13 22 11 17 6f 90 01 03 06 2d d9 de 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}