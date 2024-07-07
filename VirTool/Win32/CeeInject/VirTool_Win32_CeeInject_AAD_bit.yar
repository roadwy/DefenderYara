
rule VirTool_Win32_CeeInject_AAD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 5b 8a 1c 30 80 f3 1a f6 d3 53 5b 80 f3 26 53 5b 88 1c 30 53 5b 50 58 53 5b 84 c0 46 53 5b 84 c0 } //1
		$a_03_1 = {52 6a 40 68 90 01 04 68 90 01 04 ff 15 90 01 04 c7 45 90 01 05 8b 45 90 01 01 2d 90 01 04 89 45 90 01 01 8d 05 90 01 04 05 90 01 04 ff d0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}