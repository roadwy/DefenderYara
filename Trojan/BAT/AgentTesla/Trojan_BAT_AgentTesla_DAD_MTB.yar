
rule Trojan_BAT_AgentTesla_DAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 07 2b 18 00 11 04 11 07 09 11 07 9a 1f 10 28 ?? 00 00 0a 9c 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d db } //3
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {54 6f 42 79 74 65 } //1 ToByte
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_DAD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 59 58 5a 31 32 33 34 35 36 37 38 39 30 00 73 00 64 00 59 58 5a 31 00 } //1 夀婘㈱㐳㘵㠷〹猀搀夀婘1
		$a_01_1 = {00 59 58 5a 30 00 59 58 5a 32 00 74 00 59 58 5a 33 00 } //1 夀婘0塙㉚琀夀婘3
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_5 = {00 6d 65 74 68 6f 64 00 70 61 72 61 6d 65 74 65 72 73 00 59 58 5a 35 00 } //1 洀瑥潨d慰慲敭整獲夀婘5
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}