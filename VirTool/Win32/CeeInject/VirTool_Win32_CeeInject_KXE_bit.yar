
rule VirTool_Win32_CeeInject_KXE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7c c5 53 8b 5d ?? 6a 04 8d 46 ?? 50 8b 83 ?? ?? ?? ?? 83 c0 08 50 ff 75 ec ff d7 8b 46 28 03 45 08 53 89 83 ?? ?? ?? ?? ff 75 f0 ff 15 ?? ?? ?? ?? ff 75 f0 ff 15 ?? ?? ?? ?? 8b 45 f4 eb 03 } //1
		$a_03_1 = {99 59 f7 f9 39 55 ?? 77 0a 68 4c b4 42 00 e8 ?? ?? ?? ?? 83 7d ?? 10 8b 45 ?? 73 03 8d 45 ?? 8b 4e ?? 8a 04 10 88 45 ?? 83 f9 ?? 72 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}