
rule VirTool_Win64_PplFault_A{
	meta:
		description = "VirTool:Win64/PplFault.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 48 8b ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 45 33 c9 45 33 c0 48 8b } //1
		$a_01_1 = {48 83 ec 38 41 b8 04 00 00 00 33 d2 b9 ff ff 1f } //1
		$a_03_2 = {40 53 48 83 ec ?? 48 8b 51 ?? 48 8b d9 48 83 fa ?? 72 2c 48 8b 09 48 ff c2 48 81 fa } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}