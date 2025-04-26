
rule VirTool_Win32_Injector_DU{
	meta:
		description = "VirTool:Win32/Injector.DU,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 d4 70 e3 ac ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 eb c1 0e 55 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 3e 45 93 3e } //10
		$a_01_1 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}