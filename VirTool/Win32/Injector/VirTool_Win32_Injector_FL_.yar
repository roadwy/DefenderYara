
rule VirTool_Win32_Injector_FL_{
	meta:
		description = "VirTool:Win32/Injector.FL!!GenInjectorFL,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 f6 21 20 21 20 81 c6 11 10 11 10 89 30 83 c0 04 83 ea 01 75 e7 } //1
		$a_03_1 = {67 42 79 44 c7 ?? ?? 75 60 40 7f c7 ?? ?? 73 75 43 43 c7 ?? ?? 1d 75 7d 7f c7 ?? ?? 40 49 ce cf c7 ?? ?? ce cf cf cf e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}