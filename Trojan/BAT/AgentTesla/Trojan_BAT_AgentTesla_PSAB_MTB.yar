
rule Trojan_BAT_AgentTesla_PSAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {7e d7 00 00 04 d0 07 00 00 1b 28 2b ?? ?? ?? 6f 75 ?? ?? ?? 0d 09 2c 16 72 41 39 02 70 16 8d 87 00 00 01 28 76 ?? ?? ?? 73 77 ?? ?? ?? 7a 00 00 2b 0c 00 73 78 ?? ?? ?? 80 d7 00 00 04 00 7e d7 00 00 04 d0 07 00 00 1b 28 2b ?? ?? ?? 14 6f 79 ?? ?? ?? 00 00 28 01 00 00 2b 0a de 74 } //5
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
		$a_01_3 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}