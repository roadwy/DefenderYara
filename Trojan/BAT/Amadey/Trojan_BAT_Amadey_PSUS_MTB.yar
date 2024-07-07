
rule Trojan_BAT_Amadey_PSUS_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PSUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 00 06 03 28 90 01 01 05 00 06 6f 90 01 01 00 00 0a 13 01 20 01 00 00 00 28 90 01 01 05 00 06 39 7b ff ff ff 26 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}