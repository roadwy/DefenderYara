
rule Trojan_BAT_Androm_MBJU_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 18 5a 1f 16 58 0b 2b 4b 07 06 8e 69 5d 13 05 07 11 04 6f 90 01 01 00 00 0a 5d 13 08 06 11 05 91 13 09 11 04 11 08 6f 90 01 01 00 00 0a 13 0a 02 06 07 90 00 } //01 00 
		$a_03_1 = {11 05 02 11 0c 28 90 01 01 00 00 06 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0d 11 0d 2d a8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}