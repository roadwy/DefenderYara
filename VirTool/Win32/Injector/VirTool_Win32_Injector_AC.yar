
rule VirTool_Win32_Injector_AC{
	meta:
		description = "VirTool:Win32/Injector.AC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 55 ec ff 55 f8 89 45 e4 8b 90 01 01 e4 81 90 01 01 14 07 40 00 89 90 01 01 cc fd ff ff 8b 90 01 01 e4 90 00 } //01 00 
		$a_00_1 = {6a 40 68 00 30 00 00 8b 4d f4 8b 51 50 52 8b 45 ec 50 8b 4d 0c 51 ff 95 10 fd ff ff } //01 00 
		$a_02_2 = {8b 4d f4 03 4d 90 01 01 88 01 8b 55 90 01 01 83 c2 01 89 55 90 01 01 83 7d f8 40 7c 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}