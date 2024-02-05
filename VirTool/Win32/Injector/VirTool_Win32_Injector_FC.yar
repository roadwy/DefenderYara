
rule VirTool_Win32_Injector_FC{
	meta:
		description = "VirTool:Win32/Injector.FC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 04 00 00 00 6a 0b ff 15 90 01 02 40 00 50 ff 15 90 01 02 40 00 8b d0 8d 4d 90 01 01 ff 15 90 01 02 40 00 c7 45 fc 05 00 00 00 6a 0b 8d 55 90 01 01 52 6a 00 ff 15 90 01 02 40 00 c7 45 fc 06 00 00 00 6a 0b ff 15 90 01 02 40 00 c7 45 fc 07 00 00 00 c7 45 90 01 03 40 00 c7 45 90 01 01 08 00 00 00 8d 55 90 01 01 8d 4d 90 01 01 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_01_1 = {66 c7 40 12 c9 3b 66 c7 40 16 08 74 66 c7 40 18 02 8b 66 c7 40 1a 00 c3 66 c7 40 0a 24 04 66 c7 40 08 8b 44 66 c7 40 0c 83 c0 66 c7 40 0e 08 8b 66 c7 40 10 00 31 66 c7 40 14 4c 24 } //00 00 
	condition:
		any of ($a_*)
 
}