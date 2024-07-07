
rule Trojan_BAT_Darkcomet_ADPP_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ADPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 06 11 0a 06 91 11 04 06 91 61 28 90 01 03 0a 9c 06 17 d6 0a 28 90 01 03 0a 06 11 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}