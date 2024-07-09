
rule Trojan_BAT_AgentTesla_NSO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 aa 02 00 8d ?? ?? ?? 01 6f ?? ?? ?? 0a 00 11 04 14 72 ?? ?? ?? 70 1b 8d ?? ?? ?? 01 25 16 02 25 13 09 19 6f ?? ?? ?? 0a a2 25 17 16 } //1
		$a_80_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //GetManifestResourceNames  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}