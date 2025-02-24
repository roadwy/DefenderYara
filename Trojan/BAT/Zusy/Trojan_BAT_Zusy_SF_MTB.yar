
rule Trojan_BAT_Zusy_SF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 04 05 0e 04 6f 15 00 00 06 2c 02 17 2a 07 17 d6 0b 07 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}