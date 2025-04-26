
rule Trojan_BAT_Bladabindi_HYAL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.HYAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 03 11 05 91 06 61 09 08 91 61 b4 9c 08 04 6f ?? ?? ?? 0a 17 da fe 01 13 07 11 07 2c 04 16 0c 2b 05 00 08 17 d6 0c 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}