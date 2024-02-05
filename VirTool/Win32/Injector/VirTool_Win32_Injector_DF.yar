
rule VirTool_Win32_Injector_DF{
	meta:
		description = "VirTool:Win32/Injector.DF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 75 14 8b 45 10 0f be 04 10 8b 4d 08 03 0d e0 f3 40 00 0f be 09 33 c8 8b 45 08 03 05 e0 f3 40 00 88 08 eb bf } //01 00 
		$a_01_1 = {03 0d 34 f3 40 00 0f b6 09 33 c8 8b 45 08 03 05 34 f3 40 00 88 08 a1 e4 f3 40 00 } //01 00 
		$a_01_2 = {88 08 a1 18 fc 40 00 40 a3 18 fc 40 00 eb c0 } //00 00 
	condition:
		any of ($a_*)
 
}