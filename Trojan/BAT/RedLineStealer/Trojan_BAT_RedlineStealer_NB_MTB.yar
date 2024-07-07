
rule Trojan_BAT_RedlineStealer_NB_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 17 90 01 02 00 00 0a 11 06 91 1b 61 b4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}