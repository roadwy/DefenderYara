
rule Backdoor_Win32_PcClient_DO{
	meta:
		description = "Backdoor:Win32/PcClient.DO,SIGNATURE_TYPE_PEHSTR,42 00 42 00 0b 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 5c 63 75 72 72 65 6e 74 63 6f 6e 74 72 6f 6c 73 65 74 5c 73 65 72 76 69 63 65 73 5c } //10 system\currentcontrolset\services\
		$a_01_1 = {75 73 65 72 2d 61 67 65 6e 74 3a 20 6d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 6d 73 69 65 20 37 2e 30 3b 20 77 69 6e 64 6f 77 73 20 6e 74 20 35 2e 32 3b 20 2e 6e 65 74 20 63 6c 72 20 31 2e 31 2e 34 33 32 32 3b 20 2e 6e 65 74 20 63 6c 72 20 32 2e 30 2e 35 30 37 32 37 3b 20 69 6e 66 6f 70 61 74 68 2e 31 29 } //10 user-agent: mozilla/4.0 (compatible; msie 7.0; windows nt 5.2; .net clr 1.1.4322; .net clr 2.0.50727; infopath.1)
		$a_01_2 = {25 64 2e 65 78 65 } //10 %d.exe
		$a_01_3 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 } //10 \svchost.exe -k 
		$a_01_4 = {73 65 72 76 69 63 65 64 6c 6c } //10 servicedll
		$a_01_5 = {73 65 72 76 69 63 65 6d 61 69 6e } //10 servicemain
		$a_01_6 = {47 6c 6f 62 61 6c 5c 25 73 2d 30 34 64 2d 6d 65 74 75 78 } //2 Global\%s-04d-metux
		$a_01_7 = {47 6c 6f 62 61 6c 5c 25 73 2d 30 34 64 2d 45 56 45 4e 54 } //2 Global\%s-04d-EVENT
		$a_01_8 = {6d 79 74 68 72 65 61 64 69 64 } //2 mythreadid
		$a_01_9 = {73 65 74 77 69 6e 64 6f 77 73 68 6f 6f 6b 65 78 77 } //1 setwindowshookexw
		$a_01_10 = {6f 70 65 6e 73 63 6d 61 6e 61 67 65 72 61 } //1 openscmanagera
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=66
 
}