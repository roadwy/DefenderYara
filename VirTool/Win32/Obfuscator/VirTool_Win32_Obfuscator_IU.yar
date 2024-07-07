
rule VirTool_Win32_Obfuscator_IU{
	meta:
		description = "VirTool:Win32/Obfuscator.IU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 d0 32 02 42 b3 08 d1 e8 73 90 01 01 35 20 83 b8 ed fe cb 75 90 01 01 e2 90 00 } //1
		$a_03_1 = {ad ad 03 c7 0f ba f0 1f 73 90 01 01 60 8b d8 e8 90 01 04 61 eb 90 01 01 01 10 e2 90 00 } //1
		$a_01_2 = {6a 40 68 00 30 00 00 51 6a 00 68 4a 0d ce 09 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}