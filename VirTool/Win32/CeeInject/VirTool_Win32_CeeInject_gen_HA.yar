
rule VirTool_Win32_CeeInject_gen_HA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 fc 88 10 eb 45 8b 45 fc 99 b9 03 00 00 00 f7 f9 85 d2 74 1c 8b 15 ?? ?? ?? ?? 03 55 fc 0f be 02 83 f0 47 8b 0d 90 1b 00 03 4d fc 88 01 eb 1a 8b 15 90 1b 00 03 55 fc 0f be 02 83 f0 42 8b 0d 90 1b 00 03 4d fc 88 01 e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}