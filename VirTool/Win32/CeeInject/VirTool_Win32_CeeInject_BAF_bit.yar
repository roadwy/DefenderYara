
rule VirTool_Win32_CeeInject_BAF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BAF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e4 3b 55 10 7d 1e 8b 45 08 03 45 e4 0f b6 08 8b 55 0c 03 55 e4 0f b6 02 33 c8 8b 55 08 03 55 e4 88 0a } //1
		$a_01_1 = {c6 85 3c fe ff ff 5c c6 85 3d fe ff ff 00 c6 85 18 fe ff ff 5c c6 85 19 fe ff ff 76 c6 85 1a fe ff ff 62 c6 85 1b fe ff ff 63 c6 85 1c fe ff ff 2e c6 85 1d fe ff ff 65 c6 85 1e fe ff ff 78 c6 85 1f fe ff ff 65 } //1
		$a_01_2 = {c6 85 dc fe ff ff 57 c6 85 dd fe ff ff 72 c6 85 de fe ff ff 69 c6 85 df fe ff ff 74 c6 85 e0 fe ff ff 65 c6 85 e1 fe ff ff 50 c6 85 e2 fe ff ff 72 c6 85 e3 fe ff ff 6f c6 85 e4 fe ff ff 63 c6 85 e5 fe ff ff 65 c6 85 e6 fe ff ff 73 c6 85 e7 fe ff ff 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}