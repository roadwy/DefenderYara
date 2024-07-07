
rule Trojan_BAT_AgentTesla_PSRL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 20 00 00 0a 6f 21 00 00 0a 17 2b d3 02 28 22 00 00 0a 28 23 00 00 0a 0b 18 2b c4 07 6f 24 00 00 0a 0c 19 2b ba 06 08 6f 25 00 00 0a 0d 1a 2b af } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}