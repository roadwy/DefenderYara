
rule Trojan_BAT_AgentTesla_NFO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {04 04 02 7b } //1 Є笂
		$a_01_1 = {04 8e 69 5d 93 03 61 d2 2a } //1
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_3 = {3c 4d 61 69 6e 3e 67 5f 5f 42 61 62 6f 7c 31 } //1 <Main>g__Babo|1
		$a_01_4 = {3c 3e 63 5f 5f 44 69 73 70 6c 61 79 43 6c 61 73 73 30 5f 30 } //1 <>c__DisplayClass0_0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_NFO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 05 0e 00 00 95 6e 31 03 16 2b 01 17 17 59 7e 15 00 00 04 17 9a 20 a4 0c 00 00 95 5f 7e 15 00 00 04 17 9a 20 9c 02 00 00 95 61 61 81 09 00 00 01 23 9a 99 99 99 99 99 c9 3f 80 32 01 00 04 2b 0b 17 6a } //1
		$a_03_1 = {20 ec 04 00 00 95 e0 95 7e 1a 00 00 04 1b 9a 20 6d 12 00 00 95 61 7e 1a 00 00 04 1b 9a 20 0f 03 00 00 95 2e 03 17 2b 01 16 58 11 04 ?? 7e 1a 00 00 04 19 9a 17 95 7e 1a 00 00 04 1b 9a 20 f7 0d 00 00 } //1
		$a_01_2 = {20 a6 0b 00 00 95 5a 7e 10 00 00 04 1a 9a 20 73 12 00 00 95 58 61 81 08 00 00 01 2b 74 7e 28 00 00 04 2c 0d 7e 28 00 00 04 8e 69 d2 80 0b 00 00 04 7e 06 00 00 04 1f 41 95 7e 10 00 00 04 1a 9a 20 ec 07 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NFO_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 74 00 65 00 72 00 20 00 6e 00 75 00 67 00 66 00 67 00 66 00 67 00 66 00 6d 00 62 00 65 00 72 00 20 00 31 00 73 00 74 00 2e 00 09 00 73 00 73 00 64 00 } //1
		$a_81_1 = {44 79 6e 61 6d 69 63 44 6c 6c 49 6e 76 6f 6b 65 54 79 70 65 } //1 DynamicDllInvokeType
		$a_81_2 = {66 68 64 66 63 64 61 64 73 73 73 73 64 73 73 73 66 73 73 73 73 73 73 73 73 73 73 73 64 73 73 73 73 73 73 73 73 73 61 73 73 64 67 67 67 67 67 67 67 67 67 67 67 64 64 67 64 73 64 64 64 64 64 64 66 64 64 67 67 67 66 73 66 } //1 fhdfcdadssssdsssfsssssssssssdsssssssssassdgggggggggggddgdsddddddfddgggfsf
		$a_81_3 = {73 61 64 68 68 73 73 73 64 73 66 73 73 73 73 73 67 67 67 67 67 67 67 67 64 73 64 67 73 64 64 64 64 64 64 } //1 sadhhsssdsfsssssggggggggdsdgsdddddd
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {46 61 73 73 73 67 69 6c 68 68 64 64 } //1 Fasssgilhhdd
		$a_81_6 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_81_7 = {4e 69 6e 65 52 61 79 73 2e 4f 62 66 75 73 63 61 74 6f 72 2e 45 76 61 6c 75 61 74 69 6f 6e } //1 NineRays.Obfuscator.Evaluation
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}