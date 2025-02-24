
rule VirTool_Win64_HwBrkNetLoader_A{
	meta:
		description = "VirTool:Win64/HwBrkNetLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b fa 48 d3 e7 8d 48 ?? 48 d3 e2 48 0b fa 48 f7 d7 48 23 bc 24 90 90 00 00 00 4c 0f ab c7 48 89 bc 24 } //1
		$a_01_1 = {49 8b 80 98 00 00 00 48 8b 48 30 48 8b 10 33 c0 89 01 49 83 80 98 00 00 00 08 49 89 40 78 } //1
		$a_01_2 = {49 89 80 98 00 00 00 33 c0 49 89 40 78 b8 ff ff ff ff 48 8b 5c 24 30 48 83 c4 20 5f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}