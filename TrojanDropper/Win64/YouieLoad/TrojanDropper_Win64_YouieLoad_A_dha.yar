
rule TrojanDropper_Win64_YouieLoad_A_dha{
	meta:
		description = "TrojanDropper:Win64/YouieLoad.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 90 01 01 8d 2c 90 01 01 75 90 01 01 b8 64 86 00 00 66 39 45 04 75 90 00 } //100
		$a_01_1 = {42 8b 44 1b fc 49 83 c3 10 41 33 44 2b ec 41 89 43 ec 42 8b 44 1b f0 41 33 44 2b f0 } //50
		$a_01_2 = {8b 4c 03 fc 48 8d 40 10 33 4c 28 ec 89 48 ec 8b 4c 03 f0 33 4c 28 f0 } //50
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50) >=150
 
}