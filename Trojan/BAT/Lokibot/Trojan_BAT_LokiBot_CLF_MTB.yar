
rule Trojan_BAT_LokiBot_CLF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 f8 02 00 70 6f 90 01 04 74 90 01 04 72 90 01 04 72 90 01 04 6f 90 01 04 17 8d 90 01 04 25 16 1f 2d 9d 6f 90 01 04 0b 07 8e 90 00 } //05 00 
		$a_03_1 = {08 11 05 07 11 05 9a 1f 10 28 90 01 04 d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}