
rule Trojan_BAT_Heracles_NHC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 05 00 00 06 18 28 90 01 01 00 00 2b 7e 90 01 01 00 00 04 20 90 01 01 00 00 00 97 29 90 01 01 00 00 11 13 03 90 00 } //5
		$a_01_1 = {41 38 38 75 61 6c } //1 A88ual
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}