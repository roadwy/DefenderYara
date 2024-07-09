
rule Trojan_BAT_AgentTesla_PK_MSR{
	meta:
		description = "Trojan:BAT/AgentTesla.PK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {00 08 11 04 07 11 04 18 5a 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 } //1
		$a_00_1 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {54 6f 42 79 74 65 } //1 ToByte
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}