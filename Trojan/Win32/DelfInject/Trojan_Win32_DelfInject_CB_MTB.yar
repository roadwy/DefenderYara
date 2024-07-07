
rule Trojan_Win32_DelfInject_CB_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {35 59 54 47 54 33 34 35 36 54 4d 4f 59 54 52 35 36 51 57 } //3 5YTGT3456TMOYTR56QW
		$a_81_1 = {52 73 47 67 39 4e 4f 62 4f 63 44 61 50 49 4c 79 56 59 65 62 } //3 RsGg9NObOcDaPILyVYeb
		$a_81_2 = {54 5f 5f 31 66 66 33 32 63 63 55 } //3 T__1ff32ccU
		$a_81_3 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //3 SHGetFolderPathA
		$a_81_4 = {5c 73 61 76 65 5c 73 6f 6c 76 65 64 } //3 \save\solved
		$a_81_5 = {2a 2e 63 72 73 77 72 64 7c 2a 2e 63 72 73 77 72 64 } //3 *.crswrd|*.crswrd
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_Win32_DelfInject_CB_MTB_2{
	meta:
		description = "Trojan:Win32/DelfInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {48 69 6e 74 53 68 6f 72 74 43 75 74 73 } //3 HintShortCuts
		$a_81_1 = {70 68 69 6c 61 50 49 4e 4f 20 53 6f 66 4e } //3 philaPINO SofN
		$a_81_2 = {54 5f 5f 33 39 32 39 30 39 35 37 33 37 } //3 T__3929095737
		$a_81_3 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //3 GetLastActivePopup
		$a_81_4 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //3 GetKeyboardState
		$a_81_5 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 4e 61 6d 65 41 } //3 GetKeyboardLayoutNameA
		$a_81_6 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //3 TaskbarCreated
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}