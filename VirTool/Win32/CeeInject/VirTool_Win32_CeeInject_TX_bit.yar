
rule VirTool_Win32_CeeInject_TX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 14 18 8a 12 80 f2 bd 8d 0c 18 88 11 } //01 00 
		$a_01_1 = {8d 41 01 51 b9 ee 00 00 00 33 d2 f7 f1 59 03 ce 88 11 } //01 00 
		$a_01_2 = {30 30 45 40 42 42 54 60 92 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TX_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 03 f3 73 05 e8 90 01 04 8a 16 80 f2 4d 88 16 40 3d 90 01 04 75 e6 90 00 } //01 00 
		$a_03_1 = {81 c3 a9 0a 00 00 73 05 e8 90 01 04 89 5d fc ff 65 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}