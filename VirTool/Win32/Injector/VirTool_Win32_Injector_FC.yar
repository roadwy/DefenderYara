
rule VirTool_Win32_Injector_FC{
	meta:
		description = "VirTool:Win32/Injector.FC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 04 00 00 00 6a 0b ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 8b d0 8d 4d ?? ff 15 ?? ?? 40 00 c7 45 fc 05 00 00 00 6a 0b 8d 55 ?? 52 6a 00 ff 15 ?? ?? 40 00 c7 45 fc 06 00 00 00 6a 0b ff 15 ?? ?? 40 00 c7 45 fc 07 00 00 00 c7 45 ?? ?? ?? 40 00 c7 45 ?? 08 00 00 00 8d 55 ?? 8d 4d ?? ff 15 ?? ?? 40 00 } //1
		$a_01_1 = {66 c7 40 12 c9 3b 66 c7 40 16 08 74 66 c7 40 18 02 8b 66 c7 40 1a 00 c3 66 c7 40 0a 24 04 66 c7 40 08 8b 44 66 c7 40 0c 83 c0 66 c7 40 0e 08 8b 66 c7 40 10 00 31 66 c7 40 14 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}