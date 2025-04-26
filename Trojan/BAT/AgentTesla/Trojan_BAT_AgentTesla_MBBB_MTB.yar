
rule Trojan_BAT_AgentTesla_MBBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 } //1
		$a_01_1 = {38 30 30 34 2d 33 61 66 62 35 61 61 38 30 63 34 34 } //1 8004-3afb5aa80c44
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}