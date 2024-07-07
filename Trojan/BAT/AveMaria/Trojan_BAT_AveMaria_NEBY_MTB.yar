
rule Trojan_BAT_AveMaria_NEBY_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 8d 1e 00 00 01 13 04 7e 2e 00 00 04 02 1a 58 11 04 16 08 28 34 00 00 0a 28 71 00 00 0a 11 04 16 11 04 8e 69 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}