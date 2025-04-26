
rule Worm_Win32_Autorun_AGI{
	meta:
		description = "Worm:Win32/Autorun.AGI,SIGNATURE_TYPE_PEHSTR_EXT,7c 00 7c 00 0e 00 00 "
		
	strings :
		$a_01_0 = {25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //100 %c:\autorun.inf
		$a_01_1 = {25 63 3a 5c 64 6f 77 6e 6c 6f 61 64 73 2e 65 78 65 } //1 %c:\downloads.exe
		$a_01_2 = {25 63 3a 5c 64 6f 63 75 6d 65 6e 74 73 2e 65 78 65 } //1 %c:\documents.exe
		$a_01_3 = {25 63 3a 5c 70 69 63 73 2e 65 78 65 } //1 %c:\pics.exe
		$a_01_4 = {25 63 3a 5c 66 75 6e 2e 65 78 65 } //1 %c:\fun.exe
		$a_01_5 = {6f 70 65 6e 3d 64 6f 77 6e 6c 6f 61 64 73 2e 65 78 65 } //1 open=downloads.exe
		$a_01_6 = {6f 70 65 6e 3d 64 6f 63 75 6d 65 6e 74 73 2e 65 78 65 } //1 open=documents.exe
		$a_01_7 = {6f 70 65 6e 3d 70 69 63 73 2e 65 78 65 } //1 open=pics.exe
		$a_01_8 = {6f 70 65 6e 3d 66 75 6e 2e 65 78 65 } //1 open=fun.exe
		$a_01_9 = {65 3a 5c 6e 65 77 20 66 6f 6c 64 65 72 2e 65 78 65 } //10 e:\new folder.exe
		$a_01_10 = {66 3a 5c 6e 65 77 20 66 6f 6c 64 65 72 2e 65 78 65 } //10 f:\new folder.exe
		$a_01_11 = {67 3a 5c 6e 65 77 20 66 6f 6c 64 65 72 2e 65 78 65 } //10 g:\new folder.exe
		$a_01_12 = {5c 63 72 61 7a 79 61 2e 65 78 65 } //10 \crazya.exe
		$a_01_13 = {67 6f 64 73 20 6d 75 73 74 20 62 65 20 63 72 65 61 7a 79 21 } //10 gods must be creazy!
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10) >=124
 
}