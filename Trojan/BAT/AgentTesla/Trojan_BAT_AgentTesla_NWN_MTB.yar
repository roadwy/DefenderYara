
rule Trojan_BAT_AgentTesla_NWN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 16 16 8c ?? 00 00 01 a2 25 17 07 a2 25 13 04 14 14 18 8d ?? 00 00 01 25 17 17 9c 25 } //3
		$a_01_1 = {39 65 31 35 2d 30 38 38 37 62 31 32 39 34 37 62 34 } //3 9e15-0887b12947b4
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}