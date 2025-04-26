
rule Backdoor_Win64_Turla_B_MTB{
	meta:
		description = "Backdoor:Win64/Turla.B!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 72 6f 6e 74 61 70 70 2e 64 6c 6c } //1 frontapp.dll
		$a_01_1 = {43 6c 6f 67 70 65 72 69 6f 64 } //1 Clogperiod
		$a_01_2 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 50 49 50 45 5c 72 70 69 6e 66 6f 72 70 63 } //1 \\.\Global\PIPE\rpinforpc
		$a_01_3 = {6e 65 74 5f 70 61 73 73 77 6f 72 64 3d } //1 net_password=
		$a_01_4 = {73 61 63 72 69 6c 2e 64 6c 6c } //1 sacril.dll
		$a_01_5 = {57 00 68 00 79 00 20 00 74 00 68 00 65 00 20 00 66 00 2a 00 63 00 6b 00 20 00 6e 00 6f 00 74 00 } //1 Why the f*ck not
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}