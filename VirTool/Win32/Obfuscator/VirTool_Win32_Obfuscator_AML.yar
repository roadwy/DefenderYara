
rule VirTool_Win32_Obfuscator_AML{
	meta:
		description = "VirTool:Win32/Obfuscator.AML,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 33 c9 ac 0b c8 87 f7 ac 4b 33 c1 87 f7 8b cb e3 0b 4f aa 59 e2 e9 59 58 5b c3 } //1
		$a_03_1 = {8b d0 50 56 bf ?? ?? ?? ?? 57 53 b8 1c 00 00 00 e8 90 09 10 00 b9 [16-2f] 0d 00 00 a1 ?? ?? ?? ?? 50 b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}