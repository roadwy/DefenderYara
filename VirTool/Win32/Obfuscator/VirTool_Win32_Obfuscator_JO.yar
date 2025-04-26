
rule VirTool_Win32_Obfuscator_JO{
	meta:
		description = "VirTool:Win32/Obfuscator.JO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 c0 74 27 a9 00 00 00 80 74 07 25 ff ff 00 00 eb 09 83 c0 02 } //1
		$a_01_1 = {c3 2b 7c 24 28 89 7c 24 1c 61 c2 08 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 56 69 72 74 75 61 6c 46 72 65 65 00 6b 65 72 6e 65 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}