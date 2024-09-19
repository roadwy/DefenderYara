
rule TrojanDropper_Win64_RazSpy_ARA_MTB{
	meta:
		description = "TrojanDropper:Win64/RazSpy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 72 61 7a 73 70 79 } //2 /razspy
		$a_01_1 = {2f 72 61 7a 72 75 73 68 65 6e 69 79 65 2e 65 78 65 } //2 /razrusheniye.exe
		$a_01_2 = {65 78 70 6c 6f 72 65 72 5f 69 6e 6a 65 63 74 65 64 3d 73 75 63 63 65 73 73 } //2 explorer_injected=success
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}