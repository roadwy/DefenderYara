
rule Trojan_BAT_AgentTesla_ADK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 19 8d 5b 00 00 01 25 16 12 02 28 72 00 00 0a 9c 25 17 12 02 28 73 00 00 0a 9c 25 18 12 02 28 74 00 00 0a 9c } //2
		$a_01_1 = {52 65 73 75 6d 65 73 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 ResumesApp.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}