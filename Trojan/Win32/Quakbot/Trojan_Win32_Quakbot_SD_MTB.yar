
rule Trojan_Win32_Quakbot_SD_MTB{
	meta:
		description = "Trojan:Win32/Quakbot.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  3
		$a_80_1 = {73 74 61 67 65 72 5f 31 } //stager_1  3
		$a_80_2 = {44 64 65 44 69 73 63 6f 6e 6e 65 63 74 4c 69 73 74 } //DdeDisconnectList  3
		$a_80_3 = {4d 42 54 6f 57 43 53 45 78 } //MBToWCSEx  3
		$a_80_4 = {44 6c 67 44 69 72 53 65 6c 65 63 74 45 78 41 } //DlgDirSelectExA  3
		$a_80_5 = {53 74 72 52 65 74 54 6f 42 75 66 57 } //StrRetToBufW  3
		$a_80_6 = {44 65 6c 65 74 65 50 72 69 6e 74 50 72 6f 76 69 64 6f 72 41 } //DeletePrintProvidorA  3
		$a_80_7 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 30 39 } //SystemFunction009  3
		$a_80_8 = {48 50 41 4c 45 54 54 45 5f 55 73 65 72 46 72 65 65 } //HPALETTE_UserFree  3
		$a_80_9 = {6a 6f 79 47 65 74 54 68 72 65 73 68 6f 6c 64 } //joyGetThreshold  3
		$a_80_10 = {6d 6d 69 6f 52 65 6e 61 6d 65 57 } //mmioRenameW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3+(#a_80_10  & 1)*3) >=33
 
}