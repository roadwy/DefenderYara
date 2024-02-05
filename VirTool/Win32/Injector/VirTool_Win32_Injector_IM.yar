
rule VirTool_Win32_Injector_IM{
	meta:
		description = "VirTool:Win32/Injector.IM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 0c 03 48 3c 6b 55 f0 28 8d 84 11 f8 00 00 00 } //01 00 
		$a_01_1 = {8b 45 e8 0f be 14 10 03 ca 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 89 4d f8 eb } //01 00 
		$a_01_2 = {8b 45 ec 03 45 f4 0f be 08 33 4d f0 8b 55 ec 03 55 f4 88 0a eb } //00 00 
	condition:
		any of ($a_*)
 
}