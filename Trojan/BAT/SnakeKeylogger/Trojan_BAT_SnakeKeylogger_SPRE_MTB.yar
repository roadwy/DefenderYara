
rule Trojan_BAT_SnakeKeylogger_SPRE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 0a 0a 02 73 16 00 00 0a 0b 06 07 6f 90 01 03 0a 0c de 0d 06 2c 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}