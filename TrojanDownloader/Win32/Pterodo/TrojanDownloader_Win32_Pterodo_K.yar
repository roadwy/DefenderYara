
rule TrojanDownloader_Win32_Pterodo_K{
	meta:
		description = "TrojanDownloader:Win32/Pterodo.K,SIGNATURE_TYPE_PEHSTR,3d 00 3d 00 0f 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 43 6f 6f 6b 69 65 73 2e 63 6d 64 } //1 RunProgram="hidcon:Cookies.cmd
		$a_01_1 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 57 61 72 69 61 62 6c 65 2e 63 6d 64 } //1 RunProgram="hidcon:Wariable.cmd
		$a_01_2 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 57 61 72 69 61 62 6c 65 73 2e 63 6d 64 } //1 RunProgram="hidcon:Wariables.cmd
		$a_01_3 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 61 6e 61 6c 69 73 65 2e 63 6d 64 } //1 RunProgram="hidcon:analise.cmd
		$a_01_4 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 64 65 6c 73 6f 6c 64 2e 63 6d 64 } //1 RunProgram="hidcon:delsold.cmd
		$a_01_5 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 64 6f 77 6e 73 70 72 65 61 64 73 2e 63 6d 64 } //1 RunProgram="hidcon:downspreads.cmd
		$a_01_6 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 69 63 6c 6f 75 64 2e 63 6d 64 } //1 RunProgram="hidcon:icloud.cmd
		$a_01_7 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 69 63 6c 6f 75 64 73 2e 63 6d 64 } //1 RunProgram="hidcon:iclouds.cmd
		$a_01_8 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 73 6f 73 69 74 65 2e 63 6d 64 } //1 RunProgram="hidcon:sosite.cmd
		$a_01_9 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 75 70 64 61 74 65 73 2e 63 6d 64 } //1 RunProgram="hidcon:updates.cmd
		$a_01_10 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 77 69 6e 64 61 74 61 2e 63 6d 64 } //1 RunProgram="hidcon:windata.cmd
		$a_01_11 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 77 69 6e 68 6f 73 74 2e 63 6d 64 } //1 RunProgram="hidcon:winhost.cmd
		$a_01_12 = {3b 21 40 49 6e 73 74 61 6c 6c 45 6e 64 40 21 } //20 ;!@InstallEnd@!
		$a_01_13 = {47 55 49 4d 6f 64 65 3d 22 32 22 } //20 GUIMode="2"
		$a_01_14 = {3b 21 40 49 6e 73 74 61 6c 6c 40 21 55 54 46 2d 38 21 } //20 ;!@Install@!UTF-8!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*20+(#a_01_13  & 1)*20+(#a_01_14  & 1)*20) >=61
 
}