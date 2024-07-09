
rule Trojan_BAT_AgentTesla_NDE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 22 11 06 06 07 6f ?? ?? ?? 0a 13 07 11 07 28 ?? ?? ?? 0a 13 08 11 04 11 08 d2 6f ?? ?? ?? 0a 07 17 58 0b 07 17 fe 04 13 09 11 09 2d d4 09 } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}