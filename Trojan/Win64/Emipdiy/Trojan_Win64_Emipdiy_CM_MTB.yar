
rule Trojan_Win64_Emipdiy_CM_MTB{
	meta:
		description = "Trojan:Win64/Emipdiy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 64 71 63 62 77 30 34 31 78 64 39 2e 64 6c 6c } //3 lodqcbw041xd9.dll
		$a_01_1 = {49 74 65 72 6e 61 6c 4a 6f 62 } //3 IternalJob
		$a_01_2 = {53 65 74 50 61 74 68 } //3 SetPath
		$a_01_3 = {47 65 74 56 6f 6c 75 6d 65 4e 61 6d 65 46 6f 72 56 6f 6c 75 6d 65 4d 6f 75 6e 74 50 6f 69 6e 74 57 } //3 GetVolumeNameForVolumeMountPointW
		$a_01_4 = {53 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //3 SetProcessShutdownParameters
		$a_01_5 = {52 65 67 69 73 74 65 72 53 68 65 6c 6c 48 6f 6f 6b 57 69 6e 64 6f 77 } //3 RegisterShellHookWindow
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}