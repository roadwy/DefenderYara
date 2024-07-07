
rule VirTool_Win32_Injector_GC{
	meta:
		description = "VirTool:Win32/Injector.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 8d 8c 3d 90 01 04 8a 80 90 01 04 32 05 90 01 04 3c f3 88 01 73 04 fe c8 90 00 } //1
		$a_01_1 = {51 51 83 c0 28 dd 1c 24 ff d0 59 59 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}