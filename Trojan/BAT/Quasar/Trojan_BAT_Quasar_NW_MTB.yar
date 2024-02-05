
rule Trojan_BAT_Quasar_NW_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 28 90 01 03 0a 2a 20 90 01 03 00 fe 90 01 02 00 00 fe 90 01 02 00 20 90 01 03 00 fe 01 39 90 01 03 00 00 20 90 01 03 00 fe 90 01 02 00 00 fe 90 01 02 00 20 90 01 03 00 fe 01 39 90 01 03 00 38 90 01 03 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {67 42 59 45 42 59 45 66 75 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}