
rule Trojan_BAT_AgentTesla_SPAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 36 2b 0e 2b 35 2b da 0b 2b e8 28 90 01 03 0a 2b ee 2a 28 90 01 03 06 2b c4 28 90 01 03 0a 2b c3 06 2b c2 6f 90 01 03 0a 2b bd 28 90 01 03 06 2b b8 07 2b c0 07 2b c0 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}