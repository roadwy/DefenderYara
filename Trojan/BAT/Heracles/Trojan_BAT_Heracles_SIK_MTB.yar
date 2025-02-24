
rule Trojan_BAT_Heracles_SIK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SIK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 06 00 00 0a 6f 29 00 00 0a 11 05 28 2a 00 00 0a 13 06 7e 01 00 00 04 02 1e 58 11 06 16 11 04 1a 59 28 28 00 00 0a 11 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}