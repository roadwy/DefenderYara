
rule Trojan_BAT_AgentTesla_AAGJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 20 ea 5e 00 00 28 ?? 00 00 06 73 ?? 00 00 0a a2 6f ?? 00 00 0a 74 ?? 00 00 1b 6f ?? 00 00 0a 2b 08 06 6f ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b f1 } //3
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}