
rule VirTool_Win32_Obfuscator_ZM{
	meta:
		description = "VirTool:Win32/Obfuscator.ZM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 57 01 0f b6 4f 02 8d 84 80 10 ff ff ff 8d 54 42 d0 8d 04 92 8d 44 41 d0 0f b6 c0 c1 e0 02 e8 9e ff ff ff 43 83 c7 03 3b dd 7c d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}