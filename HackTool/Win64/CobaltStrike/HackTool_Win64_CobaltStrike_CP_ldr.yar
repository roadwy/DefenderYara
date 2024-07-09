
rule HackTool_Win64_CobaltStrike_CP_ldr{
	meta:
		description = "HackTool:Win64/CobaltStrike.CP!ldr,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {5c 53 6f 70 68 6f 73 55 6e 69 6e 73 74 61 6c 6c 2e 70 ?? 62 } //1
		$a_03_1 = {53 6f 70 68 6f 73 46 53 2e 70 ?? 62 } //1
		$a_03_2 = {00 53 6f 70 68 6f 73 4e 74 70 55 6e 69 6e 73 74 61 6c 6c 2e 70 ?? 62 } //1
		$a_03_3 = {00 53 6f 70 68 6f 73 46 53 54 65 6c 65 6d 65 74 72 79 2e 70 ?? 62 } //1
		$a_01_4 = {80 cc 10 41 89 c2 8b 85 } //3
		$a_01_5 = {01 d0 80 cc 10 41 89 c2 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=4
 
}