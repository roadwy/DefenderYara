
rule Trojan_BAT_AgentTesla_NEAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 13 00 00 06 0a 28 04 00 00 0a 06 6f 05 00 00 0a 28 06 00 00 0a 28 05 00 00 06 0b dd 06 00 00 00 26 } //10
		$a_01_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //1 WindowsFormsApp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}