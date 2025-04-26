
rule Trojan_BAT_Zusy_PSTU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7d 06 00 00 04 06 03 7d 05 00 00 04 06 15 7d 03 00 00 04 06 7c 04 00 00 04 12 00 28 01 00 00 2b 06 7c 04 00 00 04 28 10 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}