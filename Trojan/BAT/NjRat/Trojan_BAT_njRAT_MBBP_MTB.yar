
rule Trojan_BAT_njRAT_MBBP_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 11 05 11 06 20 00 00 00 00 11 06 8e b7 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 08 13 07 de 0e 90 00 } //01 00 
		$a_01_1 = {43 00 30 00 59 00 4f 00 56 00 53 00 39 00 42 00 75 00 43 00 39 00 42 00 71 00 56 00 53 00 4e 00 33 00 74 00 6a 00 58 00 41 00 55 00 6d 00 48 00 31 00 50 00 62 00 4e 00 30 00 48 00 44 00 } //00 00 
	condition:
		any of ($a_*)
 
}