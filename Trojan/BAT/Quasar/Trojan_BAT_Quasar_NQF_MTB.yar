
rule Trojan_BAT_Quasar_NQF_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {17 59 6a 06 4b 17 58 6e 5a 31 94 0f 01 03 8e 69 17 59 28 90 01 03 2b 03 2a 90 00 } //01 00 
		$a_01_1 = {6a 53 70 68 6e 64 6b 67 } //00 00  jSphndkg
	condition:
		any of ($a_*)
 
}