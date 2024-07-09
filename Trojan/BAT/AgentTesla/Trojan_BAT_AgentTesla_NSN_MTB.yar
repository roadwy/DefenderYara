
rule Trojan_BAT_AgentTesla_NSN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 7b 6b 00 00 04 7e ?? ?? ?? 04 20 ?? ?? ?? 4a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a } //5
		$a_01_1 = {41 4d 41 5a 49 4e 47 4e 45 57 57 4f 52 4c 44 5f 4c 41 55 4e 43 48 45 52 } //1 AMAZINGNEWWORLD_LAUNCHER
		$a_01_2 = {24 36 64 34 35 33 30 35 61 2d 38 30 31 66 2d 34 63 36 36 2d 38 37 62 37 2d 38 30 66 35 32 33 31 35 38 63 34 61 } //1 $6d45305a-801f-4c66-87b7-80f523158c4a
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_NSN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 62 64 31 62 31 32 65 65 2d 35 31 33 64 2d 34 35 65 34 2d 38 62 31 62 2d 39 66 62 33 61 62 36 62 61 34 35 36 } //1 $bd1b12ee-513d-45e4-8b1b-9fb3ab6ba456
		$a_01_1 = {49 4e 46 53 33 31 36 30 46 69 6e 61 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 INFS3160Final.Resources.resources
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}