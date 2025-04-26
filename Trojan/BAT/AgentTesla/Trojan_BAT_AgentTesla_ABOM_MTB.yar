
rule Trojan_BAT_AgentTesla_ABOM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 65 6c 6c 75 6c 61 72 41 75 74 6f 6d 61 74 6f 6e 53 69 6d 75 6c 61 74 69 6f 6e 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //3 CellularAutomatonSimulation.MainForm.resources
		$a_01_1 = {45 72 72 6f 72 44 65 74 65 63 74 69 6f 6e 53 69 6d 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ErrorDetectionSimulator.Properties.Resources.resources
		$a_01_2 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}