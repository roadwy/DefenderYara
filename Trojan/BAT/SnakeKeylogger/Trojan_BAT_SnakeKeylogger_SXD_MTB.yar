
rule Trojan_BAT_SnakeKeylogger_SXD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 10 00 00 0a 13 07 11 05 18 5f 2c 03 16 2b 03 17 2b 00 3a 9d 00 00 00 06 6f 90 01 03 0a 11 06 6f 90 01 03 0a 16 73 12 00 00 0a 13 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}