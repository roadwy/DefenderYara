
rule Trojan_BAT_zgRat_NF_MTB{
	meta:
		description = "Trojan:BAT/zgRat.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0c 06 00 76 6c 58 6d fe 90 01 02 00 5c fe 90 01 02 00 58 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 59 20 90 01 03 0b 61 fe 90 01 02 00 20 90 01 03 00 fe 90 01 02 00 20 90 01 03 00 5f 5a 90 00 } //01 00 
		$a_01_1 = {53 58 34 56 50 42 6e 77 72 61 } //00 00 
	condition:
		any of ($a_*)
 
}