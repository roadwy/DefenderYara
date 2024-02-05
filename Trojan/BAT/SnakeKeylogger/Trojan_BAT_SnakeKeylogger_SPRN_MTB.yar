
rule Trojan_BAT_SnakeKeylogger_SPRN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 73 0e 00 00 0a 0b 07 20 80 00 00 00 6f 90 01 03 0a 07 20 00 01 00 00 6f 90 01 03 0a 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 07 28 90 01 03 0a 04 6f 90 01 03 0a 6f 90 01 03 0a 07 18 6f 90 01 03 0a 07 17 6f 90 01 03 0a 07 07 6f 90 01 03 0a 07 6f 90 01 03 0a 6f 90 01 03 0a 0c 08 06 16 06 8e 69 90 00 } //01 00 
		$a_01_1 = {6d 00 61 00 65 00 73 00 4d 00 61 00 69 00 6e 00 2e 00 43 00 72 00 65 00 61 00 74 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}