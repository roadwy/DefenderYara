
rule VirTool_Win32_Injector_gen_EG{
	meta:
		description = "VirTool:Win32/Injector.gen!EG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4d f9 30 8c 38 9c f6 ff ff 40 3d 1d 09 00 00 7c ee 8d 85 9c f6 ff ff ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}