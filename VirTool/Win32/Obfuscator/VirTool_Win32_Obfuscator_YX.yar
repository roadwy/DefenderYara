
rule VirTool_Win32_Obfuscator_YX{
	meta:
		description = "VirTool:Win32/Obfuscator.YX,SIGNATURE_TYPE_PEHSTR,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d3 e0 8b c8 8b 45 f4 99 f7 f9 89 55 f4 b9 00 01 00 00 8b c6 99 f7 f9 89 d6 8b 45 f0 8b d6 88 14 07 ff 45 f0 43 ff 4d e8 75 } //1
		$a_01_1 = {4c 4f 6c 69 57 79 49 61 4b 72 50 4e 77 30 30 30 30 30 31 4f 59 4b 4e 79 6e 61 4e 6f 4a 69 50 35 79 6f 4f 70 73 71 45 7f 48 56 6d 33 6d 75 6c 47 } //1 佌楬祗慉牋乐ぷ〰〰伱䭙祎慮潎楊㕐潹灏煳罅噈㍭畭䝬
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}