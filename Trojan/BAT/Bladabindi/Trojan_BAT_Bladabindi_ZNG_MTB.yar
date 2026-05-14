
rule Trojan_BAT_Bladabindi_ZNG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ZNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 16 11 17 6f ?? 00 00 0a 13 18 11 0e 03 fe 04 13 19 11 19 2c 17 00 11 0b 12 18 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0e 17 58 13 0e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}