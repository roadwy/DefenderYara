
rule VirTool_Win32_Obfuscator_KN{
	meta:
		description = "VirTool:Win32/Obfuscator.KN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ac 34 55 3c c5 74 26 3c 99 74 22 3c 98 74 1e 3c bd 74 1a 3c bc 74 16 3c be 74 12 3c a1 74 0e 3c af 74 0a 3c ae 74 06 3c 5a 74 02 e2 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}