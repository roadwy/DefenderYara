
rule VirTool_Win32_Meterpreter{
	meta:
		description = "VirTool:Win32/Meterpreter,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 } //1
		$a_01_1 = {48 31 c9 41 ba 45 83 56 07 ff d5 48 31 c9 41 ba f0 b5 a2 56 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}