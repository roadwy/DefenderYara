
rule Trojan_BAT_AgentTesla_ATF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ATF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {a2 25 17 07 ?? ?? ?? ?? ?? a2 14 14 ?? ?? ?? ?? ?? 25 2d 0d 26 12 07 ?? ?? ?? ?? ?? ?? 11 07 2b 05 ?? ?? ?? ?? ?? 13 05 11 05 ?? ?? ?? ?? ?? 13 06 09 08 11 06 b4 9c 07 17 d6 0b 07 16 31 a6 08 17 d6 0c 06 17 d6 0a 06 } //10
		$a_80_1 = {54 6f 57 69 6e 33 32 } //ToWin32  1
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}