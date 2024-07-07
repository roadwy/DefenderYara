
rule Trojan_BAT_AveMaria_NAR_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 04 6f 90 01 01 00 00 0a 02 16 03 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 90 00 } //5
		$a_01_1 = {55 70 70 67 69 66 74 34 } //1 Uppgift4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}