
rule VirTool_Win32_Obfuscator_VJ{
	meta:
		description = "VirTool:Win32/Obfuscator.VJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 15 38 10 40 00 8b d0 8d 4d d0 ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 8b d0 8d 4d cc ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 8b d0 8d 4d c8 ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 8b d0 8d 4d c4 ff 15 2c 11 40 00 50 68 ?? ?? ?? ?? ff 15 38 10 40 00 } //1
		$a_00_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}