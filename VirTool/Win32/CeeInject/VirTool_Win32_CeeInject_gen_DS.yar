
rule VirTool_Win32_CeeInject_gen_DS{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 48 34 03 48 28 [0-03] 89 0d } //1
		$a_03_1 = {8a 8c 8d fc fb ff ff 80 f1 ?? f6 d1 30 0a 40 3b 45 10 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}