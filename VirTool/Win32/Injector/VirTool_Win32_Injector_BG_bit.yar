
rule VirTool_Win32_Injector_BG_bit{
	meta:
		description = "VirTool:Win32/Injector.BG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 1a ff 33 d7 88 54 18 ff 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 4e 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}