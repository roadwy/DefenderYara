
rule VirTool_Win32_Injector_GF{
	meta:
		description = "VirTool:Win32/Injector.GF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 78 fc 80 80 80 80 75 90 09 00 00 81 78 fc 80 80 80 80 90 13 31 30 [0-20] 83 c0 04 } //1
		$a_03_1 = {81 fd 21 ff 21 ff 75 90 09 00 00 81 fd 21 ff 21 ff 90 13 8b 2f [0-20] 46 [0-20] 31 f5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}