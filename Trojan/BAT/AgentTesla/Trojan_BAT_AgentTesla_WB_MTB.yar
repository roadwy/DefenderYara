
rule Trojan_BAT_AgentTesla_WB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {53 68 75 74 64 6f 77 6e 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //ShutdownEventHandler  3
		$a_80_1 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //ShutdownMode  3
		$a_80_2 = {41 73 70 69 72 69 6e 67 5f 52 6f 6f 6b 69 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //Aspiring_Rookie.Resources.resources  3
		$a_80_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggerBrowsableAttribute  3
		$a_80_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //DebuggerNonUserCodeAttribute  3
		$a_80_5 = {67 65 74 5f 4c 65 61 67 75 65 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //get_LeagueConnectionString  3
		$a_80_6 = {73 65 74 5f 53 68 6f 77 49 6e 54 61 73 6b 62 61 72 } //set_ShowInTaskbar  3
		$a_80_7 = {73 65 74 5f 44 6f 63 6b } //set_Dock  3
		$a_80_8 = {73 65 74 5f 53 68 75 74 64 6f 77 6e 53 74 79 6c 65 } //set_ShutdownStyle  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}
rule Trojan_BAT_AgentTesla_WB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.WB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 03 91 19 59 1b 59 d2 2a } //1
		$a_01_1 = {02 03 02 03 28 0a 00 00 06 25 0a 9c 06 2a } //1
		$a_01_2 = {8d 2d 00 00 01 25 d0 21 00 00 04 16 2c 03 26 26 2a 28 16 00 00 0a 2b f8 32 02 28 37 00 00 } //1
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}