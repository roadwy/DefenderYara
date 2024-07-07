
rule Trojan_BAT_Amadey_PSUV_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PSUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 00 11 05 6f 9a 00 00 0a 13 06 38 1d 00 00 00 00 11 05 11 03 6f 9b 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}