
rule Trojan_BAT_SnakeKeylogger_ABEQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 90 01 03 0a 02 07 17 58 02 8e 69 5d 91 28 90 01 03 0a 59 20 90 01 03 00 58 20 90 01 03 00 5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}