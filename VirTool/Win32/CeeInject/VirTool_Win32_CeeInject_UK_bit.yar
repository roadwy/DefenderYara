
rule VirTool_Win32_CeeInject_UK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 0b a3 14 00 2b c1 88 44 1d 90 01 01 43 83 fb 08 7c ee 90 00 } //01 00 
		$a_03_1 = {ff 75 0c 8d 34 38 ff 15 90 01 04 8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 88 06 8b 45 10 40 89 45 10 3b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}