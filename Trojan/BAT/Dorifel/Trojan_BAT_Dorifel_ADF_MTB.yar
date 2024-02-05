
rule Trojan_BAT_Dorifel_ADF_MTB{
	meta:
		description = "Trojan:BAT/Dorifel.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 1e 06 08 93 0d 09 19 59 0d 07 09 d1 13 04 12 04 28 2a 00 00 0a 28 16 00 00 0a 0b 08 17 58 0c 08 06 8e 69 32 dc } //01 00 
		$a_01_1 = {56 00 65 00 53 00 69 00 4a 00 78 00 6a 00 78 00 53 00 6f 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}