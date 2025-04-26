
rule VirTool_Win32_Obfuscator_AKG{
	meta:
		description = "VirTool:Win32/Obfuscator.AKG,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 89 45 e4 58 8b 45 e4 83 78 64 02 73 07 33 c0 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_AKG_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AKG,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6c 74 68 56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 StealthVirtualAlloc
		$a_01_1 = {53 74 6f 72 6d 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 StormVirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_AKG_3{
	meta:
		description = "VirTool:Win32/Obfuscator.AKG,SIGNATURE_TYPE_PEHSTR,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 89 45 e4 58 8b 45 e4 83 78 64 02 73 07 33 c0 e9 } //1
		$a_01_1 = {53 74 65 61 6c 74 68 56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 StealthVirtualAlloc
		$a_01_2 = {53 74 6f 72 6d 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 StormVirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}