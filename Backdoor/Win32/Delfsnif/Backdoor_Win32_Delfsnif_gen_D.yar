
rule Backdoor_Win32_Delfsnif_gen_D{
	meta:
		description = "Backdoor:Win32/Delfsnif.gen!D,SIGNATURE_TYPE_PEHSTR,41 00 3c 00 09 00 00 "
		
	strings :
		$a_01_0 = {70 69 78 63 68 65 72 20 62 6f 74 20 76 20 31 2e 31 20 62 75 69 6c 64 65 72 } //20 pixcher bot v 1.1 builder
		$a_01_1 = {45 6e 74 65 72 20 68 74 74 70 20 75 72 6c 20 74 6f 20 69 6e 64 65 78 2e 70 68 70 20 6f 66 20 62 6f 74 61 64 6d 69 6e 20 70 61 6e 65 6c 3a } //10 Enter http url to index.php of botadmin panel:
		$a_01_2 = {45 6e 74 65 72 20 6e 61 6d 65 20 6f 66 20 65 78 65 20 66 69 6c 65 3a } //10 Enter name of exe file:
		$a_01_3 = {63 6f 6d 70 69 6c 65 64 2e 2e 2e } //5 compiled...
		$a_01_4 = {70 61 63 6b 69 6e 67 2e 2e 2e } //5 packing...
		$a_01_5 = {68 74 74 70 3a 2f 2f 74 65 73 74 2e 72 75 2f 62 6f 74 61 64 6d 69 6e 2f 69 6e 64 65 78 2e 70 68 70 } //5 http://test.ru/botadmin/index.php
		$a_01_6 = {62 75 69 6c 64 2e 64 61 74 } //5 build.dat
		$a_01_7 = {75 70 78 2e 65 78 65 } //5 upx.exe
		$a_01_8 = {57 69 6e 45 78 65 63 } //5 WinExec
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5) >=60
 
}