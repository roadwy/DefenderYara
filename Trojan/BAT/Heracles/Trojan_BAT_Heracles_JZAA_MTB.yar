
rule Trojan_BAT_Heracles_JZAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.JZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 06 38 16 00 00 00 11 05 11 06 e0 58 7e 90 01 01 01 00 04 11 06 e0 91 52 11 06 17 58 13 06 11 06 6e 7e 90 01 01 01 00 04 8e 69 6a 3f da ff ff ff 90 00 } //02 00 
		$a_03_1 = {13 07 16 13 08 7e 90 01 01 00 00 0a 13 09 16 16 09 11 09 16 12 08 28 90 01 01 00 00 06 13 07 11 07 15 90 00 } //01 00 
		$a_01_2 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 } //01 00  VirtualAlloc
		$a_01_3 = {43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 } //00 00  CreateThread
	condition:
		any of ($a_*)
 
}