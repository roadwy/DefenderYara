
rule Trojan_BAT_AgentTesla_CMX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 18 d8 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a b4 9c 07 11 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 00 01 00 00 14 14 18 8d ?? ?? ?? 01 25 16 06 11 04 18 d8 18 6f ?? ?? ?? 0a a2 25 17 1f 10 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a 28 } //1
		$a_01_1 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}