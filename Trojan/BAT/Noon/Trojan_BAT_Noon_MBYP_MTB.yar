
rule Trojan_BAT_Noon_MBYP_MTB{
	meta:
		description = "Trojan:BAT/Noon.MBYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 11 12 61 13 13 11 04 17 58 11 05 8e 69 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}