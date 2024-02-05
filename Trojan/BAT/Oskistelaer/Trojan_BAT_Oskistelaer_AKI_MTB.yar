
rule Trojan_BAT_Oskistelaer_AKI_MTB{
	meta:
		description = "Trojan:BAT/Oskistelaer.AKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 74 34 00 00 01 0b 07 72 a7 00 00 70 6f } //01 00 
		$a_01_1 = {0d 02 09 17 8d 05 00 00 01 13 06 11 06 16 72 57 00 00 70 a2 00 11 06 14 28 } //00 00 
	condition:
		any of ($a_*)
 
}