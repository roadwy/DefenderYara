
rule VirTool_Win32_Injector_MRG_bit{
	meta:
		description = "VirTool:Win32/Injector.MRG!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a 8b 45 08 83 c0 01 89 45 08 b8 ?? ?? 40 00 c3 c7 45 fc 01 00 00 00 eb 99 } //2
		$a_03_1 = {8b 4d f4 33 d2 66 8b 11 81 fa 4d 5a 00 00 74 07 33 c0 e9 ?? ?? 00 00 8b 45 f4 8b 48 3c 81 c1 f8 00 00 00 39 4d 0c 7d 07 33 c0 e9 ?? ?? 00 00 8b 55 f4 8b 45 f4 03 42 3c 89 45 f8 8b 4d f8 81 39 50 45 00 00 74 07 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 8b 45 1c 50 6a 00 8b 8d ?? ?? ff ff 51 ff 15 ?? ?? 40 00 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 00 74 1a 8b 95 ?? ?? ff ff 52 8b 45 18 50 8b 4d 10 51 8b 8d ?? ?? ff ff e8 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}