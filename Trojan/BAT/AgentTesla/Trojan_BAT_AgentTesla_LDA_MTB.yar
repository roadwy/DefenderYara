
rule Trojan_BAT_AgentTesla_LDA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d } //1
		$a_01_1 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}