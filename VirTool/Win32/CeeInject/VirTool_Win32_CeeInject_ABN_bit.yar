
rule VirTool_Win32_CeeInject_ABN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b 00 66 c7 45 ?? 65 00 66 c7 45 ?? 72 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 65 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 33 00 66 c7 45 ?? 32 00 66 c7 45 ?? 2e 00 66 c7 45 ?? 64 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 00 00 } //1
		$a_01_1 = {8a 1c 30 80 f3 0e f6 d3 80 f3 cf 88 1c 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}