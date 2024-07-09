
rule VirTool_Win32_Injector_CP_bit{
	meta:
		description = "VirTool:Win32/Injector.CP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 03 85 ?? ?? ff ff 8b cf c1 e1 04 03 8d ?? ?? ff ff 33 c1 8b 8d ?? ?? ff ff 03 cf 33 c1 2b f0 8b c6 c1 e8 05 03 85 ?? ?? ff ff } //1
		$a_03_1 = {8b ce c1 e1 04 03 8d ?? ?? ff ff 33 c1 8b 8d ?? ?? ff ff 81 85 ?? ?? ff ff 47 86 c8 61 03 ce 33 c1 2b f8 ff 85 ?? ?? ff ff 83 bd ?? ?? ff ff 20 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}