
rule Trojan_BAT_AgentTesla_NNG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3f 00 3f 00 09 00 00 "
		
	strings :
		$a_81_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 34 } //10 cdn.discordapp.com/attachments/94
		$a_01_1 = {52 65 76 65 72 73 65 } //10 Reverse
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //10 GetExportedTypes
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //10 GetMethod
		$a_01_4 = {52 75 6e 74 69 6e 65 } //10 Runtine
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //10 InvokeMember
		$a_80_6 = {45 77 70 64 65 62 66 66 6b 6d 6f 6f 6c 69 6c 65 64 75 2e 51 71 69 75 6b 74 61 76 6f 6a 62 73 70 62 63 } //Ewpdebffkmooliledu.Qqiuktavojbspbc  3
		$a_80_7 = {47 68 73 6f 75 6f 72 64 6d 2e 52 78 76 69 61 64 71 78 68 75 6f 7a 76 65 6e } //Ghsouordm.Rxviadqxhuozven  3
		$a_80_8 = {4f 77 6d 67 68 75 65 73 65 77 74 77 70 6e 64 61 2e 5a 75 75 75 6b 70 78 6c 61 73 73 6b 6c 70 6d 6b } //Owmghuesewtwpnda.Zuuukpxlassklpmk  3
	condition:
		((#a_81_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=63
 
}