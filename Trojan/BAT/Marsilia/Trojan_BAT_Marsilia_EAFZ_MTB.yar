
rule Trojan_BAT_Marsilia_EAFZ_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.EAFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 05 18 5b 07 11 05 18 6f 2e 00 00 0a 1f 10 28 2f 00 00 0a 9c 11 05 18 d6 13 05 11 05 11 04 31 de } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}