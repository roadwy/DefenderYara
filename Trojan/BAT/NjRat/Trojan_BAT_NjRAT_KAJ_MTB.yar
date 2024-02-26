
rule Trojan_BAT_NjRAT_KAJ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 07 02 08 18 5a 18 6f 90 01 02 00 0a 1f 10 28 90 01 02 00 0a 6f 90 01 02 00 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d da 90 00 } //05 00 
		$a_01_1 = {a1 50 79 1f 33 0a bc 39 6e df c6 98 ef bd 2c de 30 } //00 00 
	condition:
		any of ($a_*)
 
}