
rule VirTool_Win32_VBInject_ADV{
	meta:
		description = "VirTool:Win32/VBInject.ADV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {38 00 31 00 37 00 43 00 31 00 44 00 46 00 43 00 34 00 32 00 34 00 32 00 34 00 32 00 34 00 32 00 37 00 35 00 } //01 00  817C1DFC4242424275
		$a_00_1 = {38 00 39 00 35 00 34 00 31 00 44 00 30 00 30 00 38 00 33 00 43 00 33 00 30 00 34 00 38 00 31 00 37 00 43 00 31 00 44 00 } //02 00  89541D0083C304817C1D
		$a_03_2 = {74 7b 6a 00 ff 75 1c ff 75 90 01 01 8d 45 90 01 01 50 e8 90 01 04 50 ff 75 90 01 01 6a ff e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}