
rule VirTool_Win64_Empire_G{
	meta:
		description = "VirTool:Win64/Empire.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 8b 40 ?? 48 83 e8 ?? 33 d2 b9 02 } //1
		$a_03_1 = {48 03 c8 48 8b c1 48 89 85 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 48 ff c0 } //1
		$a_03_2 = {40 55 57 48 81 ec ?? ?? 00 00 48 8d 6c 24 ?? 48 8d 7c 24 ?? b9 ?? ?? ?? ?? b8 cc cc cc cc f3 ab } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}