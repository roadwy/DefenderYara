
rule TrojanDropper_BAT_VB_W{
	meta:
		description = "TrojanDropper:BAT/VB.W,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 63 66 6a 6f 79 65 2e 65 78 65 } //2 xcfjoye.exe
		$a_01_1 = {52 75 6e 70 65 43 6c 61 73 73 } //1 RunpeClass
		$a_01_2 = {52 65 6c 65 61 73 65 5c 78 63 66 6a 6f 79 65 2e 70 64 62 } //3 Release\xcfjoye.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=6
 
}