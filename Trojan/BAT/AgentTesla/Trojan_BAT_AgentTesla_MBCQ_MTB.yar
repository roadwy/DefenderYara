
rule Trojan_BAT_AgentTesla_MBCQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 27 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 16 91 13 05 08 11 05 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 } //1
		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 00 0b 50 00 69 00 67 00 75 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}