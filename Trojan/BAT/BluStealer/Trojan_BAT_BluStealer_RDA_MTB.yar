
rule Trojan_BAT_BluStealer_RDA_MTB{
	meta:
		description = "Trojan:BAT/BluStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 07 08 09 28 90 01 04 28 90 01 04 00 28 90 01 04 28 90 01 04 28 90 01 04 00 7e 90 01 04 06 28 90 01 04 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 90 00 } //01 00 
		$a_01_1 = {75 00 47 00 2e 00 42 00 31 00 } //01 00  uG.B1
		$a_01_2 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {47 65 74 44 6f 6d 61 69 6e } //00 00  GetDomain
	condition:
		any of ($a_*)
 
}