
rule Trojan_BAT_Quasar_NQP_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 0d 00 00 0a 02 6f 90 01 03 0a 0a 03 18 18 73 90 01 03 0a 0b 06 07 6f 10 00 00 0a 90 00 } //01 00 
		$a_01_1 = {53 65 72 6f 58 65 6e 5f 44 72 6f 70 70 65 72 } //00 00  SeroXen_Dropper
	condition:
		any of ($a_*)
 
}