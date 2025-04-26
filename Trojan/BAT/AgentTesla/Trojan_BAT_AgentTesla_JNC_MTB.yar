
rule Trojan_BAT_AgentTesla_JNC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 d0 ?? ?? ?? 1b 28 ?? ?? ?? 0a a2 6f ?? ?? ?? 0a 14 17 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 } //1
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}