
rule VirTool_Win32_CeeInject_UH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UH!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 fc 0f be 18 e8 90 01 04 33 d8 8b 45 08 03 45 fc 88 18 90 00 } //01 00 
		$a_03_1 = {03 f0 89 35 90 02 10 a1 90 01 04 c1 e8 10 25 ff 7f 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}