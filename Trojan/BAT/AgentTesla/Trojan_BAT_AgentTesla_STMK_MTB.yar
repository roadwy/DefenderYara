
rule Trojan_BAT_AgentTesla_STMK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.STMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0b 07 06 72 65 00 00 70 6f 90 02 02 00 00 0a 74 02 00 00 1b 6f 90 02 02 00 00 0a 07 06 72 6d 00 00 70 6f 90 02 02 00 00 0a 74 02 00 00 1b 6f 90 02 02 00 00 0a 07 06 72 75 00 00 70 6f 90 02 02 00 00 0a 74 02 00 00 1b 6f 90 02 02 00 00 0a 02 90 00 } //1
		$a_81_1 = {4d 79 4d 65 6d 6f 72 79 4d 61 6e 61 67 65 6d 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MyMemoryManagement.Properties.Resources
		$a_81_2 = {4d 79 4d 65 6d 6f 72 79 4d 61 6e 61 67 65 6d 65 6e 74 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 MyMemoryManagement.Form1.resources
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}