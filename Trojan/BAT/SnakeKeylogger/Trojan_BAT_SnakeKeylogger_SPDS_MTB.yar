
rule Trojan_BAT_SnakeKeylogger_SPDS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 07 06 08 8f 73 00 00 01 28 90 01 03 0a 28 90 01 03 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 4d 61 72 6c 69 65 63 65 5f 41 6e 64 72 61 64 61 } //00 00 
	condition:
		any of ($a_*)
 
}