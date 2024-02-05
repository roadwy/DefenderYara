
rule Trojan_BAT_Heracles_CSSI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.CSSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 75 81 00 00 01 11 05 11 0a 75 90 01 04 11 0c 11 07 58 11 09 59 93 61 11 0b 75 90 01 04 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 90 00 } //01 00 
		$a_01_1 = {64 38 34 33 35 31 31 32 65 31 32 34 33 66 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}