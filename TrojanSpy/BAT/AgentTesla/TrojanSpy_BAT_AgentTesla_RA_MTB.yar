
rule TrojanSpy_BAT_AgentTesla_RA_MTB{
	meta:
		description = "TrojanSpy:BAT/AgentTesla.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {2f 54 68 69 73 20 70 90 02 05 6f 67 72 61 6d 20 71 61 6e 6e 6f 74 20 70 65 20 72 75 6e 20 77 6e 20 44 4f 53 20 7b 6f 64 65 90 00 } //3
		$a_01_1 = {2e 74 73 78 74 } //3 .tsxt
		$a_01_2 = {2e 72 73 72 71 } //3 .rsrq
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}