
rule HackTool_Win64_CobaltStrike_F{
	meta:
		description = "HackTool:Win64/CobaltStrike.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_01_0 = {b8 4f ec c4 4e 41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2 8a 4c 18 10 41 30 0c 38 } //1
		$a_03_1 = {31 d2 4c 8b 90 01 01 41 f7 f1 49 01 cb 48 ff c1 89 d0 8a 44 03 10 41 30 03 90 00 } //1
		$a_01_2 = {42 65 68 61 76 69 6f 72 3a } //-100 Behavior:
		$a_01_3 = {54 72 6f 6a 61 6e 3a } //-100 Trojan:
		$a_01_4 = {6d 70 61 74 74 72 69 62 75 74 65 } //-100 mpattribute
		$a_01_5 = {48 61 63 6b 54 6f 6f 6c 3a } //-100 HackTool:
		$a_01_6 = {7f 00 00 18 00 00 00 00 00 00 00 ff ff ff ff } //-100
		$a_01_7 = {f7 7f 00 00 2a 00 00 00 00 00 00 00 ff ff ff ff } //-100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*-100+(#a_01_3  & 1)*-100+(#a_01_4  & 1)*-100+(#a_01_5  & 1)*-100+(#a_01_6  & 1)*-100+(#a_01_7  & 1)*-100) >=1
 
}