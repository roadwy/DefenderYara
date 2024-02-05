
rule VirTool_Win32_CeeInject_OC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 db 33 1e 83 c6 90 01 01 f7 d3 83 c3 90 01 01 c1 cb 90 01 01 d1 c3 01 cb f8 83 d3 90 01 01 53 59 c1 c1 90 01 01 d1 c9 89 1a 83 ea 90 01 01 f8 83 df 90 01 01 81 ff 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_OC_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.OC!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {29 c9 33 0f 83 ef fc f7 d1 8d 49 e5 c1 c9 09 d1 c1 8d 49 ff 01 f1 31 f6 01 ce c1 c6 09 d1 ce 89 0b 83 eb fc 8d 52 04 81 fa 90 01 04 75 d1 90 00 } //01 00 
		$a_03_1 = {ff 33 2e e8 90 01 03 ff 58 c6 05 90 01 03 00 61 c6 05 90 01 03 00 73 c6 05 90 01 03 00 79 c6 05 90 01 03 00 63 8d 15 90 01 03 00 42 52 ff 15 90 01 03 00 50 85 c0 0f 84 90 01 03 00 90 00 } //01 00 
		$a_03_2 = {ff 10 6a 00 6a 08 68 90 01 03 00 ff 35 90 01 03 00 6a ff ff d0 8d 1d 90 01 03 00 ff 33 2e e8 90 01 03 ff 8d 0d 90 01 03 00 81 39 ff 0f 00 00 0f 87 90 01 03 00 81 19 40 02 00 00 0f 82 90 01 03 00 90 00 } //01 00 
		$a_01_3 = {00 00 63 00 78 00 72 00 72 00 66 00 69 00 6c 00 74 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}