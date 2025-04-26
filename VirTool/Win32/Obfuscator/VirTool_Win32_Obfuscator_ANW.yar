
rule VirTool_Win32_Obfuscator_ANW{
	meta:
		description = "VirTool:Win32/Obfuscator.ANW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 db 89 d2 90 90 90 90 90 90 90 90 [0-10] e8 ?? ?? ?? ff [0-ff] 5d c3 00 90 05 07 01 00 90 04 10 09 30 2d 39 41 2d 5a 61 2d 7a 90 05 30 09 30 2d 39 41 2d 5a 61 2d 7a 00 } //1
		$a_03_1 = {ff 45 f4 81 7d f4 ?? ?? ?? [01-ff] 75 90 04 01 03 d[9 20 00 [] 0-20] 90 90 90 90 [0-18] ff 45 f4 81 7d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}