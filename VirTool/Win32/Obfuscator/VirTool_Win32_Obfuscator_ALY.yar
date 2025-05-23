
rule VirTool_Win32_Obfuscator_ALY{
	meta:
		description = "VirTool:Win32/Obfuscator.ALY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 0c 00 00 "
		
	strings :
		$a_01_0 = {8a 54 14 10 30 11 } //2
		$a_03_1 = {83 40 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_2 = {83 41 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_3 = {83 42 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_4 = {83 43 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_5 = {83 46 70 01 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_6 = {ff 40 70 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_7 = {ff 41 70 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_8 = {ff 42 70 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_9 = {ff 43 70 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_10 = {ff 45 70 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
		$a_03_11 = {ff 46 70 8b ?? 04 0f b7 ?? 06 39 ?? 70 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3+(#a_03_5  & 1)*3+(#a_03_6  & 1)*3+(#a_03_7  & 1)*3+(#a_03_8  & 1)*3+(#a_03_9  & 1)*3+(#a_03_10  & 1)*3+(#a_03_11  & 1)*3) >=100
 
}