
rule HackTool_BAT_GameHack_G_MSR{
	meta:
		description = "HackTool:BAT/GameHack.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 66 75 73 65 72 } //2 Confuser
		$a_01_1 = {53 61 7a 49 6e 6a 65 63 74 6f 72 2e 65 78 65 } //2 SazInjector.exe
		$a_01_2 = {53 61 7a 49 6e 6a 65 63 74 6f 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SazInjector.Resources.resources
		$a_01_3 = {41 73 73 65 6d 62 6c 79 20 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 Assembly System.Reflection
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}