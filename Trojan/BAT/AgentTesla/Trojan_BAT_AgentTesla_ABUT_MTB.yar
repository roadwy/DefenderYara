
rule Trojan_BAT_AgentTesla_ABUT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 75 64 6f 6b 75 43 57 4c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 SudokuCWL.Properties.Resources.resources
		$a_01_1 = {65 65 35 33 39 33 61 65 2d 65 33 65 33 2d 34 34 66 36 2d 39 37 37 33 2d 37 38 35 33 62 37 31 38 36 35 39 38 } //1 ee5393ae-e3e3-44f6-9773-7853b7186598
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}