
rule Trojan_BAT_XLoader_RDA_MTB{
	meta:
		description = "Trojan:BAT/XLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6b 64 46 49 68 } //02 00 
		$a_01_1 = {02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 } //00 00 
	condition:
		any of ($a_*)
 
}