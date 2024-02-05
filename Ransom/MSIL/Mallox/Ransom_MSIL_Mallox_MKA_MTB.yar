
rule Ransom_MSIL_Mallox_MKA_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 61 60 13 07 1f 0e 13 0e 38 90 01 03 ff 11 0b 74 90 01 03 1b 8e 69 13 08 17 13 09 1b 13 0e 38 90 01 03 ff 11 04 74 90 01 03 01 11 05 11 0a 75 90 01 03 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 09 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 90 01 03 0a 26 1a 13 0e 38 90 01 03 ff 11 09 17 58 13 09 1b 13 0e 38 90 01 03 ff 11 09 11 07 31 08 19 13 0e 38 90 01 03 ff 1f 0d 2b f5 11 04 75 90 01 03 01 6f 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}