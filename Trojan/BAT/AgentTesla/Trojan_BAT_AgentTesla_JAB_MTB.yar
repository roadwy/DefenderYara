
rule Trojan_BAT_AgentTesla_JAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 06 07 61 0c 73 ?? ?? ?? 0a 25 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 25 72 ?? ?? ?? 70 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 25 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0d 72 ?? ?? ?? 70 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 06 66 0c 72 ?? ?? ?? 70 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 06 18 62 0c 72 ?? ?? ?? 70 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 06 18 63 0c 09 6f } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}