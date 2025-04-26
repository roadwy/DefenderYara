
rule Trojan_BAT_LummaC_SWA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 24 8d 15 00 00 01 25 d0 06 00 00 04 28 11 00 00 0a 80 02 00 00 04 20 4b 05 00 00 8d 15 00 00 01 25 d0 07 00 00 04 28 11 00 00 0a 80 03 00 00 04 14 80 04 00 00 04 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}