
rule VirTool_Win32_Injector_GB{
	meta:
		description = "VirTool:Win32/Injector.GB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 0f b6 0c 19 03 ca 66 81 e1 ff 00 79 09 66 49 66 81 c9 00 ff 66 41 0f bf d1 8b 8d 34 ff ff ff 8a 14 1a 8a 19 32 da 88 19 8b 8d 44 ff ff ff 03 c1 e9 57 ff ff ff } //01 00 
		$a_01_1 = {54 00 4d 00 50 00 4e 00 45 00 54 00 4c 00 4f 00 41 00 44 00 } //00 00 
	condition:
		any of ($a_*)
 
}