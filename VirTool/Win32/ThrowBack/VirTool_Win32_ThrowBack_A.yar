
rule VirTool_Win32_ThrowBack_A{
	meta:
		description = "VirTool:Win32/ThrowBack.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 53 51 56 ff 90 01 05 8b f8 85 ff 90 01 06 6a 00 53 ff 75 e0 57 56 ff 90 01 05 85 c0 90 01 05 50 33 c0 50 50 57 50 50 56 ff 90 01 05 89 45 e4 ff 90 01 05 83 f8 08 90 00 } //1
		$a_03_1 = {50 6a 00 68 00 00 00 02 ff 90 01 05 8b f0 ff 90 01 05 85 f6 90 01 05 50 68 eb 01 02 00 56 ff 90 01 05 83 7d fc 00 90 01 05 50 6a 01 6a 01 6a 00 68 00 00 00 02 ff 75 fc ff 90 01 05 85 c0 90 01 02 ff 75 f8 ff 90 01 05 ff 90 01 05 ff 75 fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}