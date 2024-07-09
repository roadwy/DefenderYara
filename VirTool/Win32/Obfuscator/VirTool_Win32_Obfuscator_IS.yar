
rule VirTool_Win32_Obfuscator_IS{
	meta:
		description = "VirTool:Win32/Obfuscator.IS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 8d 45 e8 50 8d 45 ec 50 ff 15 ?? 20 40 00 } //1
		$a_00_1 = {c7 45 fc 00 30 40 00 } //1
		$a_02_2 = {6a 00 8d 45 e4 50 6a 0c 8d 45 f0 50 ff 75 e8 ff 15 ?? 20 40 00 } //1
		$a_02_3 = {6a 00 8d 45 e4 50 6a 19 8d 45 f4 50 ff 75 ec ff 15 ?? 20 40 00 } //1
		$a_02_4 = {8d 45 e4 50 6a 40 68 ?? ?? ?? 00 68 00 30 40 00 ff 15 ?? 20 40 00 68 00 30 40 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}