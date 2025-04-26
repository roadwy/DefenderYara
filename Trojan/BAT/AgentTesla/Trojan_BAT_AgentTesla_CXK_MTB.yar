
rule Trojan_BAT_AgentTesla_CXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 28 ?? ?? ?? 0a 23 00 00 00 00 00 80 73 40 59 28 ?? ?? ?? 0a b7 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 17 d6 0c } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //1 esaBmorF
		$a_01_4 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 } //1 gnirtS46
		$a_01_5 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}