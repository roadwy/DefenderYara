
rule Trojan_BAT_AgentTesla_NFL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {2b 01 17 17 59 7e 1c 00 00 04 18 9a 20 6b 0a 00 00 95 5f 7e 1c 00 00 04 18 9a 20 c6 10 00 00 95 61 61 81 05 00 00 01 7e 2a 00 00 04 1f 46 95 7e 1c 00 00 04 18 9a 20 bd 00 00 00 95 33 25 7e 2a 00 00 04 1f 46 } //10
		$a_01_1 = {01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1b 00 00 00 04 } //10
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_5 = {67 65 74 5f 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //1 get_BaseDirectory
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=24
 
}