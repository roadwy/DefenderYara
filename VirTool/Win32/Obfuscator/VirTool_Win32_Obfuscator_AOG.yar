
rule VirTool_Win32_Obfuscator_AOG{
	meta:
		description = "VirTool:Win32/Obfuscator.AOG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f ?? ?? ?? ?? 30 14 38 90 90 90 90 90 90 90 90 } //1
		$a_03_1 = {6b 88 5c 24 ?? c6 44 24 ?? 72 c6 44 24 ?? 6e 88 5c 24 ?? c6 44 24 ?? 6c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}