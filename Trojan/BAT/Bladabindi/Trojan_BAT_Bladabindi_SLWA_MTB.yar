
rule Trojan_BAT_Bladabindi_SLWA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SLWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 72 ?? 01 00 70 6f 30 00 00 0a 11 05 72 ?? 01 00 70 6f 31 00 00 0a 11 05 17 6f 32 00 00 0a 11 05 17 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}