
rule Ransom_Win32_NefilimGo_PA_MTB{
	meta:
		description = "Ransom:Win32/NefilimGo.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_81_0 = {2e 6c 6f 63 6b } //1 .lock
		$a_81_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_2 = {73 74 6f 70 74 68 65 77 6f 72 6c 64 } //1 stoptheworld
		$a_81_3 = {6d 61 69 6e 2e 53 61 76 65 4e 6f 74 65 2e 66 75 6e 63 } //1 main.SaveNote.func
		$a_81_4 = {6d 61 69 6e 2e 46 69 6c 65 53 65 61 72 63 68 2e 66 75 6e 63 } //1 main.FileSearch.func
		$a_81_5 = {6d 61 69 6e 2e 67 65 74 64 72 69 76 65 73 } //1 main.getdrives
		$a_81_6 = {6d 61 69 6e 2e 55 6e 69 78 46 69 6c 65 } //1 main.UnixFile
		$a_81_7 = {6d 61 69 6e 2e 47 65 6e 65 72 61 74 65 52 61 6e 64 6f 6d 42 79 74 65 73 } //1 main.GenerateRandomBytes
		$a_81_8 = {70 61 74 68 2f 66 69 6c 65 70 61 74 68 2e 53 6b 69 70 44 69 72 } //1 path/filepath.SkipDir
		$a_81_9 = {75 6e 72 65 61 63 68 61 62 6c 65 75 73 65 72 65 6e 76 2e 64 6c 6c } //1 unreachableuserenv.dll
		$a_81_10 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //1 at  fp= is  lr: of  on  pc= sp: sp=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=9
 
}