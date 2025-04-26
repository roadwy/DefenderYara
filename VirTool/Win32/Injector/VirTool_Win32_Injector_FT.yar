
rule VirTool_Win32_Injector_FT{
	meta:
		description = "VirTool:Win32/Injector.FT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 07 07 00 01 00 ff d6 8b 4c 24 ?? 57 51 ff d0 } //2
		$a_03_1 = {83 c0 34 50 8b 44 24 ?? 83 c2 08 52 50 ff 54 24 ?? 8b 4c 24 ?? 8b 51 28 03 54 24 } //2
		$a_01_2 = {52 65 76 64 46 69 6c 65 } //1 RevdFile
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule VirTool_Win32_Injector_FT_2{
	meta:
		description = "VirTool:Win32/Injector.FT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 00 07 00 01 00 8d 85 ?? ?? ff ff 83 c0 7d } //2
		$a_03_1 = {ff d0 83 ec 14 8b 85 ?? ?? ff ff 8b 50 28 8b 85 ?? ?? ff ff 01 c2 8b 85 ?? ?? ff ff 89 90 90 b0 00 00 00 } //2
		$a_01_2 = {43 72 65 61 4f 65 46 69 6c 65 41 } //1 CreaOeFileA
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule VirTool_Win32_Injector_FT_3{
	meta:
		description = "VirTool:Win32/Injector.FT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 02 07 00 01 00 8d 8d ?? ?? ff ff 51 ff b5 ?? ?? ff ff ff 55 ?? 89 45 } //2
		$a_03_1 = {83 c0 34 50 ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff ff 55 ?? 8b 95 ?? ?? ff ff 8b 4a 28 03 8d ?? ?? ff ff 8b 85 ?? ?? ff ff 89 88 b0 00 00 00 } //2
		$a_01_2 = {6b 65 72 6e 65 6c 33 32 2e 64 56 6c } //1 kernel32.dVl
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}