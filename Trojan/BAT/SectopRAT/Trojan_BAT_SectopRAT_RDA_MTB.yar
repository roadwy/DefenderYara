
rule Trojan_BAT_SectopRAT_RDA_MTB{
	meta:
		description = "Trojan:BAT/SectopRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 75 74 64 6f 6f 72 5f 61 63 74 69 76 69 74 79 5f 61 70 70 5f 77 69 74 68 5f 6d 61 6e 61 67 65 72 } //01 00  outdoor_activity_app_with_manager
		$a_01_1 = {55 6e 69 63 6f 6d } //01 00  Unicom
		$a_01_2 = {4d 69 64 65 61 } //00 00  Midea
	condition:
		any of ($a_*)
 
}