
rule Trojan_BAT_AgentTesla_FGI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 7e ?? ?? ?? 04 16 14 28 ?? ?? ?? 06 a2 25 17 7e ?? ?? ?? 04 16 14 28 ?? ?? ?? 06 a2 25 18 7e ?? ?? ?? 04 19 14 28 ?? ?? ?? 06 a2 25 19 7e ?? ?? ?? 04 19 14 28 ?? ?? ?? 06 a2 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 80 ?? ?? ?? 04 7e ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 08 16 20 00 10 00 00 } //10
		$a_81_1 = {52 61 63 65 43 6f 72 65 2e 64 6c 6c } //1 RaceCore.dll
		$a_81_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}