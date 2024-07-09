
rule HackTool_Win64_CobaltStrike_C_{
	meta:
		description = "HackTool:Win64/CobaltStrike.C!!CobaltStrike.C64,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_03_0 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 } //1
		$a_03_1 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b } //1
		$a_03_2 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c } //1
		$a_01_3 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3 } //1
		$a_01_4 = {0f af d1 44 8b c8 b8 1f 85 eb 51 f7 e2 41 8b c1 44 8b c2 33 d2 41 c1 e8 05 41 f7 f0 } //10
		$a_01_5 = {42 65 68 61 76 69 6f 72 3a } //-100 Behavior:
		$a_01_6 = {54 72 6f 6a 61 6e 3a } //-100 Trojan:
		$a_01_7 = {6d 70 61 74 74 72 69 62 75 74 65 } //-100 mpattribute
		$a_01_8 = {48 61 63 6b 54 6f 6f 6c 3a } //-100 HackTool:
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*-100+(#a_01_6  & 1)*-100+(#a_01_7  & 1)*-100+(#a_01_8  & 1)*-100) >=11
 
}