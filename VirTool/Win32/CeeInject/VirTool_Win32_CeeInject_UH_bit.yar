
rule VirTool_Win32_CeeInject_UH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 } //1
		$a_03_1 = {03 f0 89 35 [0-10] a1 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}