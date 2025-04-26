
rule Trojan_BAT_Bladabindi_UXO_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.UXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 02 11 04 91 06 11 04 06 8e b7 5d 91 61 08 11 04 08 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}