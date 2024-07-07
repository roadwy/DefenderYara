
rule TrojanSpy_BAT_AgentTesla{
	meta:
		description = "TrojanSpy:BAT/AgentTesla,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 16 0b 2b 2d 03 25 4b 04 06 1f 0f 5f 95 61 54 04 06 1f 0f 5f 04 06 1f 0f 5f 95 03 25 1a 58 10 01 4b 61 20 84 e2 03 78 58 9e 06 17 58 0a 07 17 58 0b 07 02 37 cf 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanSpy_BAT_AgentTesla_2{
	meta:
		description = "TrojanSpy:BAT/AgentTesla,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 67 68 79 74 75 74 67 66 6e 6d 64 66 67 2e 4d 79 } //1 fghytutgfnmdfg.My
		$a_01_1 = {50 4f 4f 59 55 47 48 59 46 55 47 2e 4d 79 } //1 POOYUGHYFUG.My
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //2 ConfuserEx v1.0.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}