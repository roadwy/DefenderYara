
rule TrojanSpy_BAT_AgentTesla_SM_MTB{
	meta:
		description = "TrojanSpy:BAT/AgentTesla.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {03 11 04 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 04 07 6f ?? ?? ?? ?? 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 08 11 05 6f [0-08] 6f ?? 00 00 0a 17 da 33 03 17 2b 01 16 2c ?? 16 0b 07 2c 04 07 17 d6 0b ?? 04 ?? ?? ?? ?? 11 04 } //10
		$a_80_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } //XOR_Decrypt  1
		$a_80_2 = {6d 49 4f 54 41 } //mIOTA  1
		$a_80_3 = {49 6f 2e 78 79 } //Io.xy  1
		$a_80_4 = {44 61 74 61 62 61 73 65 4d 61 6e 61 67 65 72 2e 41 2e 72 65 73 6f 75 72 63 65 73 } //DatabaseManager.A.resources  1
		$a_80_5 = {44 61 74 61 62 61 73 65 4d 61 6e 61 67 65 72 2e 46 72 6d 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //DatabaseManager.FrmMenu.resources  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=15
 
}