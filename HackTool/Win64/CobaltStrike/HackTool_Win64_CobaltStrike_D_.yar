
rule HackTool_Win64_CobaltStrike_D_{
	meta:
		description = "HackTool:Win64/CobaltStrike.D!!CobaltStrike.D64,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_03_0 = {00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 } //1
		$a_03_1 = {69 68 69 68 69 6b ?? ?? 69 6b 69 68 69 6b } //1
		$a_03_2 = {2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f 2e 2c } //1
		$a_01_3 = {4c 63 c2 4d 03 c0 42 0f 10 04 c0 48 8b c1 f3 0f 7f 01 c3 } //1
		$a_03_4 = {b9 00 00 10 00 e8 [0-3c] ba 7f 66 04 40 8b c8 48 8b [0-08] 89 08 48 8b 4b 20 } //10
		$a_01_5 = {42 65 68 61 76 69 6f 72 3a } //-100 Behavior:
		$a_01_6 = {54 72 6f 6a 61 6e 3a } //-100 Trojan:
		$a_01_7 = {6d 70 61 74 74 72 69 62 75 74 65 } //-100 mpattribute
		$a_01_8 = {48 61 63 6b 54 6f 6f 6c 3a } //-100 HackTool:
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*10+(#a_01_5  & 1)*-100+(#a_01_6  & 1)*-100+(#a_01_7  & 1)*-100+(#a_01_8  & 1)*-100) >=11
 
}