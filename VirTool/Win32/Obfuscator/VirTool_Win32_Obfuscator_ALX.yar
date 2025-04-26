
rule VirTool_Win32_Obfuscator_ALX{
	meta:
		description = "VirTool:Win32/Obfuscator.ALX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db } //1
		$a_01_1 = {8b 42 08 89 45 e0 8b 4d f0 8b 51 0c 89 55 e8 ff 75 e8 ff 75 e0 ff 75 dc ff 75 e4 8b 45 fc ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}