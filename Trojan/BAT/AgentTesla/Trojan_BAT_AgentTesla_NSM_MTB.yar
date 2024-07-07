
rule Trojan_BAT_AgentTesla_NSM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 17 da 6f 90 01 03 0a 08 11 05 08 6f 90 01 03 0a 5d 6f 90 01 03 0a da 13 06 09 11 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0d 11 05 17 d6 13 05 11 05 11 04 31 c5 90 00 } //1
		$a_01_1 = {50 45 44 4f 49 57 44 45 4a 55 49 4a 44 } //1 PEDOIWDEJUIJD
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}