
rule HackTool_Linux_CymulatPayload_A{
	meta:
		description = "HackTool:Linux/CymulatPayload.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //CymulateEDRScenarioExecutor  1
		$a_80_1 = {61 74 74 61 63 6b 5f 69 64 } //attack_id  1
		$a_80_2 = {73 63 65 6e 61 72 69 6f 5f 69 64 } //scenario_id  1
		$a_80_3 = {25 73 2f 67 6c 6f 62 61 6c 5f 61 70 74 5f 73 63 65 6e 61 72 69 6f 73 5f 6f 75 74 70 75 74 2e 74 78 74 } //%s/global_apt_scenarios_output.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}