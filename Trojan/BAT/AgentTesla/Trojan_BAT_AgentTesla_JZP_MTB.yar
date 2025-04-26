
rule Trojan_BAT_AgentTesla_JZP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 06 11 04 28 ?? ?? ?? 0a 07 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d ca } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //1 SuspendLayout
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}