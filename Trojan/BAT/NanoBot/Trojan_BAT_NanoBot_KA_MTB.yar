
rule Trojan_BAT_NanoBot_KA_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f 90 01 01 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 02 8e 69 fe 04 13 06 11 06 2d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}