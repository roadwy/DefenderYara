
rule VirTool_Win32_CeeInject_ABQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 db 2b 1e f7 db f8 83 d6 04 f7 db 8d 5b f1 c1 cb 09 d1 c3 31 d3 4b 89 da c1 c2 09 d1 ca f7 da 53 8f 07 } //1
		$a_03_1 = {85 c0 0f 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 5e 83 c6 10 31 d2 4a 81 e2 ?? ?? ?? ?? 8d 38 31 c0 57 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}