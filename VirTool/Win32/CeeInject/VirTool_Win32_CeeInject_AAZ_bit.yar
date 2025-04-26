
rule VirTool_Win32_CeeInject_AAZ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b 4d 0c 7d 1a 8b 55 08 03 55 ?? 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 ?? 88 18 } //1
		$a_03_1 = {55 8b ec 83 ec 08 e8 ?? ?? ?? ?? 0f af 45 0c 89 45 ?? c7 45 ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 8b 4d 08 89 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}