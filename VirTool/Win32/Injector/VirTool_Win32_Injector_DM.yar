
rule VirTool_Win32_Injector_DM{
	meta:
		description = "VirTool:Win32/Injector.DM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 04 0a 8d 55 d4 8d 45 d8 52 50 90 03 07 07 6a 02 ff d3 83 c4 0c e9 c7 77 ff ff 90 90 90 00 } //1
		$a_01_1 = {66 3b b5 78 ff ff ff 0f 8f bb 00 00 00 0f bf fe } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}