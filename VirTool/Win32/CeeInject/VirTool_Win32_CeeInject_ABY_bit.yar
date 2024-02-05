
rule VirTool_Win32_CeeInject_ABY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABY!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 75 90 01 01 5b 8a 82 90 00 } //01 00 
		$a_03_1 = {30 04 37 4e 79 f5 90 09 05 00 e8 90 00 } //01 00 
		$a_03_2 = {88 0c 07 8a 4d 90 01 01 47 88 0c 07 8a 4d 90 01 01 22 ca 0a 4d 90 01 01 47 88 0c 07 03 75 90 01 01 8b 45 90 01 01 47 3b 30 90 00 } //01 00 
		$a_03_3 = {7c ea 50 56 a3 90 01 04 ff 15 90 01 04 a3 90 01 04 a1 90 01 04 a3 90 01 04 33 c0 39 35 90 01 04 76 1f 8b 0d 90 01 04 8a 8c 08 90 01 04 8b 15 90 01 04 88 0c 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}