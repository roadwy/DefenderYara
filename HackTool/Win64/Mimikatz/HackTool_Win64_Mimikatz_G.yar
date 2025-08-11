
rule HackTool_Win64_Mimikatz_G{
	meta:
		description = "HackTool:Win64/Mimikatz.G,SIGNATURE_TYPE_PEHSTR,28 00 28 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8d 6e 30 48 8d 0d } //10
		$a_01_1 = {48 8d 94 24 b0 00 00 00 48 8d 0d } //10
		$a_01_2 = {4c 8d 85 30 01 00 00 48 8d 15 } //10
		$a_01_3 = {0f b6 4c 24 30 85 c0 0f 45 cf 8a c1 } //10
		$a_01_4 = {44 8b 45 80 85 c0 0f 84 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=40
 
}