
rule Trojan_BAT_AgentTesla_AAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 05 2b 1f 00 09 08 11 05 18 6f 7b 00 00 0a 1f 10 28 7c 00 00 0a 6f 7d 00 00 0a 00 00 11 05 18 58 13 05 11 05 08 6f 1c 00 00 0a fe 04 13 06 11 06 2d d1 } //2
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 2e 00 41 00 70 00 70 00 } //1 Sudoku.App
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}