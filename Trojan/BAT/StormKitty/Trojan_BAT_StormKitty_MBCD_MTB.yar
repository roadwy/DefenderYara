
rule Trojan_BAT_StormKitty_MBCD_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.MBCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 16 0c 2b 20 08 02 07 02 8e 69 5d 91 58 06 07 91 58 20 ff 00 00 00 5f 0c 06 07 08 28 09 00 00 06 07 17 58 0b 07 20 00 01 00 00 32 d8 } //01 00 
		$a_01_1 = {57 15 02 08 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 0d 00 00 00 04 00 00 00 04 00 00 00 0c 00 00 00 11 00 00 00 14 00 00 00 05 } //00 00 
	condition:
		any of ($a_*)
 
}