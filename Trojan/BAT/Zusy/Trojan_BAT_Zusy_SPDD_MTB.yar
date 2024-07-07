
rule Trojan_BAT_Zusy_SPDD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SPDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 03 00 00 04 6f 90 01 03 0a 05 0e 08 02 8e 69 6f 90 01 03 0a 0a 06 0b 2b 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}