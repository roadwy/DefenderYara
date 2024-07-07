
rule VirTool_Win32_CeeInject_AAV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 04 24 bf 90 01 04 81 ef 90 01 04 83 ec 04 89 3c 24 bb 90 01 04 81 eb 90 01 04 83 ec 04 89 1c 24 be 00 00 00 00 83 ec 04 89 34 24 be 90 01 04 83 ec 04 89 34 24 ff 15 90 00 } //1
		$a_01_1 = {31 c9 2b 0a f7 d9 83 c2 04 8d 49 dd 01 f9 49 8d 39 c6 06 00 01 0e 83 ee fc 83 c3 fc 83 fb 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}