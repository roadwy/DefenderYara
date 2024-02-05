
rule VirTool_Win32_VBInject_ADC_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 00 00 00 f0 31 d8 d1 c8 c1 c3 08 e2 f7 } //01 00 
		$a_03_1 = {5e 8b 7c 24 0c b9 90 01 04 57 f3 66 a5 5f b8 04 00 00 00 90 02 10 e8 0e 00 00 00 90 02 10 01 c1 81 f9 90 02 10 75 90 01 01 ff e7 81 34 0f 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}