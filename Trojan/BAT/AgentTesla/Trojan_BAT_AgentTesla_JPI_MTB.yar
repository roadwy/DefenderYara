
rule Trojan_BAT_AgentTesla_JPI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 06 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 18 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f } //1
		$a_81_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}