
rule Trojan_BAT_Quasar_NQR_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 0b 07 07 8e 69 18 59 28 90 01 02 00 0a 0c 08 20 90 01 02 00 00 fe 01 13 05 11 05 39 90 01 02 00 00 90 00 } //01 00 
		$a_01_1 = {53 69 4d 61 79 53 65 72 76 69 63 65 2e 4c 6f 61 64 65 72 } //00 00  SiMayService.Loader
	condition:
		any of ($a_*)
 
}