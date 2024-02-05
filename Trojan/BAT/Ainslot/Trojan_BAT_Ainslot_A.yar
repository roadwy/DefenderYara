
rule Trojan_BAT_Ainslot_A{
	meta:
		description = "Trojan:BAT/Ainslot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 08 8e 69 32 b7 06 28 4b 00 00 06 6f 29 00 00 0a 2d 1a 28 2a 00 00 0a 28 49 00 00 06 28 4a 00 00 06 28 2b 00 00 0a 28 2c 00 00 0a 26 } //00 00 
	condition:
		any of ($a_*)
 
}