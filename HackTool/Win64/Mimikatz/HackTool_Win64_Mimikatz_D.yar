
rule HackTool_Win64_Mimikatz_D{
	meta:
		description = "HackTool:Win64/Mimikatz.D,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 43 72 64 41 ff 15 } //10
		$a_01_1 = {24 43 72 64 41 48 ff 15 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}