
rule VirTool_Win32_Obfuscator_WS{
	meta:
		description = "VirTool:Win32/Obfuscator.WS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 63 00 69 00 71 00 74 00 7a 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 mciqtz32.dll
		$a_03_1 = {6a 02 6a 00 68 60 d0 09 01 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 83 ec 0c e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 48 3b 8d 04 08 8b 40 28 60 b4 40 2a c4 0f 8f ?? ?? ?? ?? 61 c3 } //1
		$a_03_2 = {c6 09 01 c2 00 00 90 09 10 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 ff 35 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}