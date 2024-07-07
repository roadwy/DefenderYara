
rule Trojan_O97M_Obfuse_JI_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.JI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 4e 61 6d 65 20 3d 20 22 2a 2e 6a 70 67 20 3b 20 2a 2e 6a 70 65 20 3b 20 2a 2e 62 6d 70 20 3b 20 2a 2e 67 69 66 20 3b 20 2a 2e 61 76 69 20 3b 20 2a 2e 77 61 76 20 3b 20 2a 2e 6d 69 64 20 3b 20 2a 2e 6d 70 67 20 3b 20 2a 2e 6d 70 32 20 3b 20 2a 2e 6d 70 33 20 3b 20 2a 2e 7a 69 70 20 3b 20 2a 2e 72 61 72 20 3b 20 2a 2e 61 72 6a 20 3b 20 2a 2e 68 74 6d 20 3b 20 2a 2e 68 74 6d 6c } //1 FileName = "*.jpg ; *.jpe ; *.bmp ; *.gif ; *.avi ; *.wav ; *.mid ; *.mpg ; *.mp2 ; *.mp3 ; *.zip ; *.rar ; *.arj ; *.htm ; *.html
		$a_01_1 = {4b 69 6c 6c 20 66 73 2e 46 6f 75 6e 64 46 69 6c 65 73 28 6a 29 } //1 Kill fs.FoundFiles(j)
		$a_01_2 = {4c 6f 6f 6b 49 6e 20 3d 20 22 43 3a 5c 20 3b 20 44 3a 5c 20 3b 20 45 3a 5c 20 3b 20 46 3a 5c 20 3b 20 47 3a 5c 20 3b 20 48 3a 5c 20 3b 20 49 3a 5c 20 3b 20 4a 3a 5c 20 3b 20 4b 3a 5c 20 3b 20 4c 3a 5c 20 3b 20 4d 3a 5c 20 3b 20 4e 3a 5c 20 3b 20 4f 3a 5c 20 3b 20 50 3a 5c 20 3b 20 51 3a 5c 20 3b 20 52 3a 5c 20 3b 20 53 3a 5c 20 3b 20 54 3a 5c 20 3b 20 55 3a 5c 20 3b 20 56 3a 5c 20 3b 20 57 3a 5c 20 3b 20 58 3a 5c 20 3b 20 59 3a 5c 20 3b 20 5a 3a 5c } //1 LookIn = "C:\ ; D:\ ; E:\ ; F:\ ; G:\ ; H:\ ; I:\ ; J:\ ; K:\ ; L:\ ; M:\ ; N:\ ; O:\ ; P:\ ; Q:\ ; R:\ ; S:\ ; T:\ ; U:\ ; V:\ ; W:\ ; X:\ ; Y:\ ; Z:\
		$a_01_3 = {57 6f 72 64 42 61 73 69 63 2e 44 69 73 61 62 6c 65 41 75 74 6f 4d 61 63 72 6f 73 20 2d 31 } //1 WordBasic.DisableAutoMacros -1
		$a_01_4 = {53 65 6c 65 63 74 69 6f 6e 2e 46 6f 6e 74 2e 41 6e 69 6d 61 74 69 6f 6e 20 3d 20 77 64 41 6e 69 6d 61 74 69 6f 6e 42 6c 69 6e 6b 69 6e 67 42 61 63 6b 67 72 6f 75 6e 64 } //1 Selection.Font.Animation = wdAnimationBlinkingBackground
		$a_01_5 = {4b 69 6c 6c 20 28 58 4c 53 2e 53 74 61 72 74 75 70 50 61 74 68 20 2b 20 43 68 72 28 39 32 29 20 2b 20 43 68 72 28 36 36 29 20 2b 20 43 68 72 28 31 31 31 29 20 2b 20 43 68 72 28 31 31 31 29 20 2b 20 43 68 72 28 31 30 37 29 20 2b 20 43 68 72 28 34 39 29 20 2b 20 43 68 72 28 34 36 29 29 } //1 Kill (XLS.StartupPath + Chr(92) + Chr(66) + Chr(111) + Chr(111) + Chr(107) + Chr(49) + Chr(46))
		$a_01_6 = {72 65 67 65 64 69 74 2e 52 65 67 57 72 69 74 65 20 22 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 22 22 2c 20 31 } //1 regedit.RegWrite ""HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools"", 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}