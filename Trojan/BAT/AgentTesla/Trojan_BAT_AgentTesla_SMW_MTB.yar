
rule Trojan_BAT_AgentTesla_SMW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 12 02 28 47 00 00 0a 6f 48 00 00 0a 00 03 12 02 28 49 00 00 0a 6f 48 00 00 0a 00 03 12 02 28 4a 00 00 0a 6f 48 00 00 0a 00 2b 15 03 6f 4b 00 00 0a 19 58 04 31 03 16 2b 01 17 13 04 11 04 2d be } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}