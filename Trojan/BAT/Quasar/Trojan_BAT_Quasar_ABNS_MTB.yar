
rule Trojan_BAT_Quasar_ABNS_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ABNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {08 16 07 16 1f 10 28 90 01 03 06 7e 90 01 03 04 08 16 07 1f 0f 1f 10 28 90 01 03 06 7e 90 01 03 04 06 07 28 90 01 03 06 7e 90 01 03 04 06 18 28 90 01 03 06 7e 90 01 03 04 06 28 90 01 03 06 0d 90 00 } //01 00 
		$a_01_1 = {41 00 6e 00 6c 00 66 00 46 00 70 00 6e 00 69 00 6d 00 68 00 65 00 65 00 61 00 } //00 00  AnlfFpnimheea
	condition:
		any of ($a_*)
 
}