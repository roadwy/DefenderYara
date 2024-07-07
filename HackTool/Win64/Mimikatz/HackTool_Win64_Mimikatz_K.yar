
rule HackTool_Win64_Mimikatz_K{
	meta:
		description = "HackTool:Win64/Mimikatz.K,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 06 07 01 08 0a 0e 00 03 05 02 0f 0d 09 0c 04 } //10
		$a_01_1 = {bb 03 00 00 c0 e9 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}