
rule Trojan_BAT_AgentTesla_NCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 28 09 00 00 06 ?? ?? 6f 0f 00 00 0a 28 10 00 00 0a ?? ?? 17 d6 8d 11 00 00 01 ?? ?? ?? ?? ?? 6f 11 00 00 0a 26 ?? 6f 12 00 00 0a ?? 0c 2b 00 08 2a } //5
		$a_80_1 = {25 66 69 6c 65 73 53 74 72 69 6e 67 73 25 } //%filesStrings%  2
		$a_80_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  2
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=11
 
}