
rule VirTool_Win32_Obfuscator_ACS{
	meta:
		description = "VirTool:Win32/Obfuscator.ACS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 06 88 45 ?? 8b 45 ?? 8a 14 16 88 14 06 8b 45 ?? 8a 55 ?? 88 14 06 ff 45 ?? 81 7d } //1
		$a_03_1 = {68 e8 03 00 00 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 ff 77 ?? e8 ?? ?? ?? ?? 89 c6 09 f6 75 (04|07) 31 c0 (|) eb e9 } //1
		$a_03_2 = {ff 77 38 68 00 40 02 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 24 39 77 38 75 ?? 8d 05 ?? ?? ?? ?? 89 47 08 8d 05 ?? ?? ?? ?? 89 47 0c 8d 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}