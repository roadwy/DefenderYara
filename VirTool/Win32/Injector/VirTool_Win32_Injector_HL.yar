
rule VirTool_Win32_Injector_HL{
	meta:
		description = "VirTool:Win32/Injector.HL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 07 0f 81 8d fe ff ff } //1
		$a_01_1 = {72 78 0f 81 3e ff ff ff eb } //1
		$a_01_2 = {39 f1 0f 81 aa 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}