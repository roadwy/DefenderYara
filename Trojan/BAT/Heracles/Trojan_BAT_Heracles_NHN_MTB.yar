
rule Trojan_BAT_Heracles_NHN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 03 00 00 0a 2b 05 72 90 01 02 00 70 26 2b 05 72 90 01 02 00 70 20 90 01 02 00 00 2b 05 72 90 01 02 00 70 fe 90 01 02 00 2b 05 72 90 01 02 00 70 00 2b 05 90 00 } //01 00 
		$a_01_1 = {6e 4a 42 30 61 6e } //00 00 
	condition:
		any of ($a_*)
 
}