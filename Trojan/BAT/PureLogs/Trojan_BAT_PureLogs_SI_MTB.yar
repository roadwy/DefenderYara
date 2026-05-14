
rule Trojan_BAT_PureLogs_SI_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 00 02 28 0c 00 00 06 7d 04 00 00 04 de 2b 26 00 00 de 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}