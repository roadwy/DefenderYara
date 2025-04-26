
rule Trojan_BAT_Cerbu_SOC_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.SOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 21 00 00 0a 25 72 01 00 00 70 6f 22 00 00 0a 25 72 17 00 00 70 6f ?? ?? ?? 0a 25 16 6f 24 00 00 0a 25 17 6f ?? ?? ?? 0a 28 26 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}