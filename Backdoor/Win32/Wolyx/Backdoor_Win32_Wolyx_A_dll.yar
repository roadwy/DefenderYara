
rule Backdoor_Win32_Wolyx_A_dll{
	meta:
		description = "Backdoor:Win32/Wolyx.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,12 00 10 00 0b 00 00 "
		
	strings :
		$a_01_0 = {7b 41 46 41 46 42 32 45 45 2d 38 33 37 43 2d 34 45 41 35 2d 42 39 33 33 2d 39 39 38 46 39 34 41 45 43 36 35 34 7d 5c } //4 {AFAFB2EE-837C-4EA5-B933-998F94AEC654}\
		$a_01_1 = {41 73 75 74 61 74 53 73 65 63 69 76 72 65 53 6d 75 6e 45 } //4 AsutatSsecivreSmunE
		$a_01_2 = {3a 28 46 6c 6f 6f 70 79 29 } //4 :(Floopy)
		$a_01_3 = {20 63 6c 6f 75 64 63 6f 6d 32 2e 64 6c 6c } //4  cloudcom2.dll
		$a_01_4 = {50 61 73 73 77 6f 72 64 73 20 6f 66 20 41 75 74 6f 20 43 6f 6d 70 6c 65 74 65 } //2 Passwords of Auto Complete
		$a_01_5 = {54 68 69 6e 6b 20 53 70 61 63 65 } //2 Think Space
		$a_01_6 = {50 72 6f 74 6f 63 6f 6c 5f 43 61 74 61 6c 6f 67 39 5c 43 61 74 61 6c 6f 67 5f 45 6e 74 72 69 65 73 } //2 Protocol_Catalog9\Catalog_Entries
		$a_01_7 = {74 68 65 77 6f 72 6c 64 2e 65 78 65 } //1 theworld.exe
		$a_01_8 = {74 74 72 61 76 65 6c 65 72 2e 65 78 65 } //1 ttraveler.exe
		$a_01_9 = {54 53 65 6e 64 44 72 69 76 65 72 44 69 72 46 69 6c 65 73 54 68 72 65 61 64 } //1 TSendDriverDirFilesThread
		$a_01_10 = {54 53 65 6e 64 4b 65 79 4c 6f 67 49 6e 66 6f 54 68 72 65 61 64 } //1 TSendKeyLogInfoThread
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=16
 
}