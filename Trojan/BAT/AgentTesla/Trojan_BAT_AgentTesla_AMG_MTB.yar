
rule Trojan_BAT_AgentTesla_AMG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_03_0 = {17 da 13 06 16 0b 2b 1e 09 06 07 6f ?? ?? ?? 0a 13 07 11 07 28 ?? ?? ?? 0a 13 08 11 04 08 11 08 b4 9c 07 17 d6 0b 07 11 06 31 dd 08 17 d6 0c 06 17 d6 0a 06 11 05 31 c2 } //10
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  2
		$a_80_3 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //InvokeMethod  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=14
 
}