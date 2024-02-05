
rule Trojan_BAT_SnakeKeylogger_SPAT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 00 02 09 02 7b 90 01 03 04 09 6f 90 01 03 0a 28 90 01 03 06 13 04 11 04 16 fe 01 13 05 11 05 2c 06 11 04 13 06 2b 10 00 08 17 58 0c 08 07 8e 69 32 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}