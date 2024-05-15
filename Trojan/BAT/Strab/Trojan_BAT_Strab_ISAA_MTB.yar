
rule Trojan_BAT_Strab_ISAA_MTB{
	meta:
		description = "Trojan:BAT/Strab.ISAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 11 11 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 90 01 01 11 13 7e 90 01 01 00 00 04 28 90 01 01 01 00 06 a5 90 01 01 00 00 01 61 d2 90 00 } //01 00 
		$a_01_1 = {41 6e 67 65 6c 6f } //01 00  Angelo
		$a_01_2 = {43 6f 72 72 65 63 74 } //01 00  Correct
		$a_01_3 = {52 65 6d 6f 74 65 4f 62 6a 65 63 74 73 } //00 00  RemoteObjects
	condition:
		any of ($a_*)
 
}