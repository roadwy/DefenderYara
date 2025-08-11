
rule HackTool_Win64_Mimikatz_H{
	meta:
		description = "HackTool:Win64/Mimikatz.H,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {b9 14 00 00 00 f3 aa 48 8d 3d } //10
		$a_01_1 = {48 8b ca f3 aa 48 8d 3d } //10
		$a_01_2 = {8b ca f3 aa 48 8d 3d } //10
		$a_01_3 = {8d 50 14 8b ca 44 8d 48 01 44 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}