
rule VirTool_Win32_Obfuscator_EO{
	meta:
		description = "VirTool:Win32/Obfuscator.EO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d3 5c 5c 2e 5c } //1
		$a_01_1 = {c7 45 d7 6d 61 69 6c } //1
		$a_01_2 = {c7 45 db 73 6c 6f 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}