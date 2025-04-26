
rule VirTool_Win32_Obfuscator_BK{
	meta:
		description = "VirTool:Win32/Obfuscator.BK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 5d 83 3b 00 0f 85 a5 00 00 00 fc 89 1b 8b 4b 0c 33 c0 ff d1 8b 4b 10 e3 2f } //1
		$a_01_1 = {61 9d c3 83 ec 54 8b fc 8b 76 0c 8b d7 ac 84 c0 74 03 aa eb f8 e8 0b 00 00 00 20 6e 6f 74 20 66 6f 75 6e 64 00 5e ac aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}