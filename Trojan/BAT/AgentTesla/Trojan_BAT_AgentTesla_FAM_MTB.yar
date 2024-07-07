
rule Trojan_BAT_AgentTesla_FAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 1c 08 07 11 04 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 04 18 58 13 04 11 04 07 6f 90 01 01 00 00 0a 32 da 90 00 } //3
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 55 00 49 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 SudokuUI.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}