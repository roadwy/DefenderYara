
rule Trojan_BAT_AveMaria_NEAR_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 86 00 00 0a 28 66 00 00 0a 20 90 01 04 28 0a 00 00 06 28 52 00 00 06 28 51 00 00 06 6f 87 00 00 0a 90 00 } //5
		$a_01_1 = {6f 96 00 00 0a 1e 5b 6f 97 00 00 0a 6f 98 00 00 0a 06 11 04 06 6f 99 00 00 0a 1e 5b 6f 97 00 00 0a 6f 9a 00 00 0a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}