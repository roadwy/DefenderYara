
rule Trojan_BAT_AgentTesla_NSA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 66 05 00 70 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 1f 64 73 ?? ?? 00 0a 1f 10 6f ?? ?? 00 0a 0a 28 ?? ?? 00 0a 0b 73 ?? ?? 00 0a 0c 08 03 2d 18 07 06 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 6f ?? ?? 00 0a 2b 16 07 06 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? 00 0a } //5
		$a_01_1 = {61 71 61 79 67 64 2e 52 65 73 6f 75 72 63 65 73 } //1 aqaygd.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NSA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 37 33 65 34 36 65 37 33 2d 62 39 32 33 2d 34 39 65 34 2d 61 62 33 62 2d 61 36 31 34 31 62 64 61 64 33 31 38 } //1 $73e46e73-b923-49e4-ab3b-a6141bdad318
		$a_01_1 = {50 6f 6e 67 5f 66 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Pong_fr.Resources.resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}