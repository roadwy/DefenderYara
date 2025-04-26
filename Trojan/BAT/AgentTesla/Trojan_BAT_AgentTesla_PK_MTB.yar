
rule Trojan_BAT_AgentTesla_PK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff b6 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 d4 00 00 00 28 00 00 00 04 01 00 00 57 02 00 00 da 00 00 00 07 00 00 00 78 01 00 00 67 } //1
		$a_01_1 = {31 64 65 35 65 39 30 33 62 36 31 62 } //1 1de5e903b61b
		$a_01_2 = {4c 43 44 2e 50 72 6f 70 65 72 74 69 65 73 } //1 LCD.Properties
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_PK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {0b 16 02 8e b7 17 da 13 06 13 05 2b 28 07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f ?? ?? ?? 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 06 31 d2 } //10
		$a_80_1 = {52 43 32 44 65 63 72 79 70 74 } //RC2Decrypt  1
		$a_80_2 = {58 4f 52 5f 44 45 43 } //XOR_DEC  1
		$a_80_3 = {52 69 6a 6e 44 65 63 72 79 70 74 } //RijnDecrypt  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=12
 
}