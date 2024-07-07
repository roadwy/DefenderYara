
rule Trojan_BAT_AgentTesla_DAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 69 6d 75 6c 61 74 65 75 72 5f 64 65 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Simulateur_des.Properties.Resources.resources
		$a_01_1 = {53 69 6d 75 6c 61 74 65 75 72 5f 64 65 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 Simulateur_des.Form1.resources
		$a_01_2 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}