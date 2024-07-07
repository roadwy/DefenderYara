
rule HackTool_Win64_Mimikatz_I{
	meta:
		description = "HackTool:Win64/Mimikatz.I,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 6c 24 30 f3 0f 7f 2d } //10
		$a_01_1 = {0f 10 45 f0 66 48 0f 7e c0 0f 11 05 } //10
		$a_01_2 = {48 8b fa 48 8b f1 eb } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}