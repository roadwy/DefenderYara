
rule VirTool_Win32_DelfInject_DN_bit{
	meta:
		description = "VirTool:Win32/DelfInject.DN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 4d ec ba 90 01 04 b8 90 01 04 e8 90 01 04 8b 45 ec e8 90 01 04 50 90 00 } //01 00 
		$a_03_1 = {bf 01 00 00 00 8b 45 fc e8 90 01 04 8b 55 fc 0f b6 54 3a ff 33 c2 50 8b 45 f8 e8 90 01 04 8b 55 f8 0f b6 54 1a ff 33 c2 5a 33 d0 8d 45 90 01 01 e8 90 01 04 8b 55 90 01 01 8d 45 f0 e8 90 01 04 43 8b 45 f8 e8 90 01 04 3b d8 7e 05 bb 01 00 00 00 47 4e 75 af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}