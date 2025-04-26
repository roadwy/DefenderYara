
rule Trojan_BAT_AgentTesla_NAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d dd } //1
		$a_01_1 = {63 37 39 66 34 63 39 2d 36 37 36 62 2d 34 32 37 63 2d 39 31 35 39 2d 36 63 30 30 33 37 62 34 63 36 } //1 c79f4c9-676b-427c-9159-6c0037b4c6
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_NAC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 17 00 00 0a 25 17 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 25 11 06 6f ?? 00 00 0a 25 6f ?? 00 00 0a 26 25 } //5
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_2 = {44 65 66 61 75 6c 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Default.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}