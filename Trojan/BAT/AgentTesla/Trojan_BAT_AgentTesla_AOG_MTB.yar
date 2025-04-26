
rule Trojan_BAT_AgentTesla_AOG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {da 13 05 16 13 06 2b 21 07 11 04 11 06 ?? ?? ?? ?? ?? 13 07 11 07 ?? ?? ?? ?? ?? 13 08 08 06 11 08 b4 9c 11 06 17 d6 13 06 11 06 11 05 31 d9 06 17 d6 0a 11 04 17 d6 13 04 11 04 09 31 bb } //10
		$a_80_1 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  2
		$a_80_2 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //ReadOnlyDictionary  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=14
 
}