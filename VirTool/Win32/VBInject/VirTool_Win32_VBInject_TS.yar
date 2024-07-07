
rule VirTool_Win32_VBInject_TS{
	meta:
		description = "VirTool:Win32/VBInject.TS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 64 5f 42 79 5f 54 68 65 5f 50 72 6f 44 69 47 79 2f 2f 2f 49 6e 64 65 74 65 63 74 61 62 6c 65 73 2e 6e 65 74 } //1 Mod_By_The_ProDiGy///Indetectables.net
		$a_01_1 = {23 00 24 00 24 00 23 00 23 00 } //1 #$$##
		$a_01_2 = {64 00 65 00 6d 00 6f 00 6e 00 69 00 6f 00 36 00 36 00 36 00 76 00 69 00 70 00 } //1 demonio666vip
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}