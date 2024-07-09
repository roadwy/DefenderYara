
rule Trojan_BAT_AgentTesla_NGD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 61 16 0b 2b 4b 11 04 14 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 18 8d ?? ?? ?? 01 25 16 06 8c ?? ?? ?? 01 a2 25 17 07 8c ?? ?? ?? 01 a2 14 14 28 ?? ?? ?? 0a a5 ?? ?? ?? 01 13 05 11 05 28 ?? ?? ?? 0a 13 06 02 09 06 11 06 d2 28 ?? ?? ?? 06 07 17 58 0b 07 17 fe 04 13 07 11 07 2d ab 08 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NGD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 ?? ?? ?? 0a 20 ?? ?? ?? 00 da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 07 11 06 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b8 } //1
		$a_01_1 = {24 30 38 39 38 45 33 33 44 2d 43 45 35 44 2d 34 30 41 38 2d 39 36 35 37 2d 34 36 36 32 34 31 36 37 33 35 41 45 } //1 $0898E33D-CE5D-40A8-9657-4662416735AE
		$a_01_2 = {5f 41 00 5f 42 00 5f 43 00 5f 44 00 5f 45 00 5f 46 } //1
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}