
rule Trojan_BAT_Bladabindi_GRR_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 59 01 00 70 6f 2a 00 00 0a 0a 06 72 5f 01 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}