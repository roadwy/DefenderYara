
rule Trojan_BAT_AgentTesla_RAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 18 d8 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 17 d6 13 04 } //10
		$a_01_1 = {73 00 65 00 70 00 79 00 54 00 74 00 65 00 47 00 } //10 sepyTteG
		$a_01_2 = {4c 61 74 65 47 65 74 } //1 LateGet
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}
rule Trojan_BAT_AgentTesla_RAM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 95 b6 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 d7 00 00 00 2f 00 00 00 ad 01 00 00 67 03 00 00 5b 02 00 00 f8 01 00 00 99 04 00 00 02 00 00 00 5a 00 00 00 04 00 00 00 10 00 00 00 17 00 00 00 eb 00 00 00 6a 01 00 00 32 00 00 00 02 00 00 00 01 00 00 00 09 00 00 00 0e 00 00 00 16 00 00 00 11 00 00 00 19 } //1
		$a_81_1 = {45 33 32 43 43 42 46 33 2d 43 46 39 34 2d 34 30 41 31 2d 38 32 35 30 2d 39 32 38 42 39 43 32 44 30 44 34 42 } //1 E32CCBF3-CF94-40A1-8250-928B9C2D0D4B
		$a_81_2 = {53 65 73 73 69 6f 6e 5f 49 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Session_Initialization.Properties.Resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}