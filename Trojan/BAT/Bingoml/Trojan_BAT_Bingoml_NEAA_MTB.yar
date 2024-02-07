
rule Trojan_BAT_Bingoml_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Bingoml.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {7e 04 00 00 04 2d 3d 72 33 00 00 70 0a 06 28 17 00 00 0a 0b 28 18 00 00 0a 07 16 07 8e 69 6f 19 00 00 0a 0a 28 1a 00 00 0a 06 6f 1b 00 00 0a } //02 00 
		$a_01_1 = {54 00 6b 00 31 00 44 00 57 00 45 00 4e 00 59 00 53 00 6b 00 64 00 4c 00 53 00 6b 00 64 00 4c 00 52 00 45 00 5a 00 4c 00 4a 00 41 00 3d 00 3d 00 } //00 00  Tk1DWENYSkdLSkdLREZLJA==
	condition:
		any of ($a_*)
 
}