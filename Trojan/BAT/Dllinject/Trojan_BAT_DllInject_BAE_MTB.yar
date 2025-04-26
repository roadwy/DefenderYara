
rule Trojan_BAT_DllInject_BAE_MTB{
	meta:
		description = "Trojan:BAT/DllInject.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {3c 42 72 6f 77 73 65 72 5f 4a 61 76 61 73 63 72 69 70 74 4d 65 73 73 61 67 65 52 65 63 65 69 76 65 64 3e 62 5f 5f 32 32 5f 30 } //1 <Browser_JavascriptMessageReceived>b__22_0
		$a_81_1 = {3c 41 6e 69 6d 61 74 65 49 6e 6a 65 63 74 65 64 3e 64 5f 5f 35 33 } //1 <AnimateInjected>d__53
		$a_81_2 = {73 76 67 33 32 31 5f 43 6f 70 79 33 } //1 svg321_Copy3
		$a_81_3 = {46 69 6c 65 48 42 4f 70 74 73 47 61 74 65 } //1 FileHBOptsGate
		$a_81_4 = {46 6f 6c 64 65 72 44 69 73 70 6c 61 79 5f 4d 6f 75 73 65 4c 65 61 76 65 } //1 FolderDisplay_MouseLeave
		$a_81_5 = {43 61 72 64 48 6f 6c 64 65 72 5f 4d 6f 75 73 65 44 6f 75 62 6c 65 43 6c 69 63 6b } //1 CardHolder_MouseDoubleClick
		$a_81_6 = {4b 72 6e 6c 55 49 2e 65 78 65 } //1 KrnlUI.exe
		$a_81_7 = {4b 72 6e 6c 55 49 2d 6d 61 69 6e 5c 4b 72 6e 6c 55 49 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4b 72 6e 6c 55 49 2e 70 64 62 } //1 KrnlUI-main\KrnlUI\obj\Release\KrnlUI.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}