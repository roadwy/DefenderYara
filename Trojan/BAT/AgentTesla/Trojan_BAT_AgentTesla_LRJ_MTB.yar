
rule Trojan_BAT_AgentTesla_LRJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 09 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 ?? ?? ?? 00 73 ?? ?? ?? 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f } //1
		$a_01_1 = {68 64 66 73 64 73 66 } //1 hdfsdsf
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}