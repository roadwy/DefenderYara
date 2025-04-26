
rule VirTool_Win32_Obfuscator_ABJ{
	meta:
		description = "VirTool:Win32/Obfuscator.ABJ,SIGNATURE_TYPE_PEHSTR,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b3 5e 30 18 40 fe cb 84 db 75 02 b3 5e e2 f3 } //1
		$a_01_1 = {0f ce 85 c3 83 da 73 c1 fe 62 c1 c7 46 0f ba f2 58 4f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}