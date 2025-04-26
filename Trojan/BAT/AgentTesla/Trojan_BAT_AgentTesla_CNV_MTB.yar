
rule Trojan_BAT_AgentTesla_CNV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 d8 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c } //1
		$a_01_1 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_2 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {50 61 72 61 6d 58 41 72 72 61 79 } //1 ParamXArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}