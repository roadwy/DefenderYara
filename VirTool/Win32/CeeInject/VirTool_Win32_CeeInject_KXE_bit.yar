
rule VirTool_Win32_CeeInject_KXE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {7c c5 53 8b 5d 90 01 01 6a 04 8d 46 90 01 01 50 8b 83 90 01 04 83 c0 08 50 ff 75 ec ff d7 8b 46 28 03 45 08 53 89 83 90 01 04 ff 75 f0 ff 15 90 01 04 ff 75 f0 ff 15 90 01 04 8b 45 f4 eb 03 90 00 } //01 00 
		$a_03_1 = {99 59 f7 f9 39 55 90 01 01 77 0a 68 4c b4 42 00 e8 90 01 04 83 7d 90 01 01 10 8b 45 90 01 01 73 03 8d 45 90 01 01 8b 4e 90 01 01 8a 04 10 88 45 90 01 01 83 f9 90 01 01 72 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}