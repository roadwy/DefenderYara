
rule Trojan_BAT_Heracles_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 17 58 11 04 5d 91 59 20 00 01 00 00 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}