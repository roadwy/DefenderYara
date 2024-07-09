
rule VirTool_Win32_Obfuscator_AFD{
	meta:
		description = "VirTool:Win32/Obfuscator.AFD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 68 97 c3 0a 00 e8 ?? ?? ff ff 83 c4 0c } //1
		$a_03_1 = {56 6a 02 5e 39 75 08 72 ?? 53 57 6a 02 5f 8d 1c 36 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_AFD_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AFD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 10 8b 1d ?? ?? ?? ?? 83 fb ff 74 2d 85 db 74 13 8d 34 9d 90 1b 00 66 90 90 ff 16 83 ee 04 83 eb 01 75 f6 c7 04 24 } //1
		$a_03_1 = {c7 44 24 08 00 04 00 00 c7 44 24 04 60 50 40 00 c7 04 24 00 00 00 00 ff 15 40 50 40 00 83 ec 0c 8d 7c 24 12 be ?? 40 40 00 b9 0e 00 00 00 f3 a4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}