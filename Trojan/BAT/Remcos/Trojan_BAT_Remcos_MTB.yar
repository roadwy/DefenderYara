
rule Trojan_BAT_Remcos_MTB{
	meta:
		description = "Trojan:BAT/Remcos!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 06 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 06 25 28 19 00 90 01 02 28 04 00 90 01 02 28 0b 00 90 01 02 7d 05 00 90 01 02 13 01 20 00 00 90 01 02 7e 2c 00 90 01 02 7b 4b 00 90 01 02 3a b0 ff 90 01 02 26 20 00 00 90 01 02 38 a5 ff ff ff 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}