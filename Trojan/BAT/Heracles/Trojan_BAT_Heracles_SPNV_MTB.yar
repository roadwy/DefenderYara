
rule Trojan_BAT_Heracles_SPNV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 91 61 28 ?? ?? ?? 0a 07 11 04 17 6a 58 07 8e 69 6a 5d d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}