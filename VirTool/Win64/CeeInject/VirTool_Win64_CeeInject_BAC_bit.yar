
rule VirTool_Win64_CeeInject_BAC_bit{
	meta:
		description = "VirTool:Win64/CeeInject.BAC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 63 d0 48 8b 45 f0 48 8d 1c 02 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 30 48 8b 45 28 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 89 c1 8b 45 fc 99 f7 f9 89 d0 48 63 d0 } //1
		$a_01_1 = {48 8b 45 b0 48 8d 1c 02 48 8b 4d e0 e8 e1 fe ff ff 88 03 48 83 45 e0 02 83 45 bc 01 8b 45 bc 3b 45 ac 7c d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}