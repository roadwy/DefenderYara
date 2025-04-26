
rule Trojan_BAT_Heracles_SEI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 13 01 00 70 6f 0e 00 00 06 6f 29 00 00 06 72 1f 01 00 70 6f 10 00 00 06 09 6f 17 00 00 06 16 6f 05 00 00 06 74 05 00 00 02 25 72 2d 01 00 70 6f 08 00 00 06 72 43 01 00 70 6f 0a 00 00 06 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}