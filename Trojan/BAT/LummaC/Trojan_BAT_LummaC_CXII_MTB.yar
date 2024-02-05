
rule Trojan_BAT_LummaC_CXII_MTB{
	meta:
		description = "Trojan:BAT/LummaC.CXII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 03 03 28 90 01 04 17 59 fe 01 13 05 38 90 01 04 02 02 8e 69 17 59 91 1f 70 61 13 01 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}