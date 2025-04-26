
rule VirTool_Win32_Obfuscator_SM{
	meta:
		description = "VirTool:Win32/Obfuscator.SM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 28 03 c7 89 45 08 8b 45 08 ff d0 6a 00 } //1
		$a_01_1 = {32 ca ff 45 0c ff 45 08 83 7d 08 10 75 15 33 db 89 5d 08 eb 10 ff 45 0c 83 7d 0c 04 75 07 89 5d 0c eb 02 33 db 88 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}