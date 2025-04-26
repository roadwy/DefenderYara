
rule Trojan_BAT_LummaC_CXII_MTB{
	meta:
		description = "Trojan:BAT/LummaC.CXII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 03 28 ?? ?? ?? ?? 17 59 fe 01 13 05 38 ?? ?? ?? ?? 02 02 8e 69 17 59 91 1f 70 61 13 01 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}