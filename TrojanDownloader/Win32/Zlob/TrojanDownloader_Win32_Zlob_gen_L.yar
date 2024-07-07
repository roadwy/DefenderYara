
rule TrojanDownloader_Win32_Zlob_gen_L{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 42 00 47 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 5f 00 31 00 } //2 MyBGTransfer_1
		$a_01_1 = {5c 50 43 20 44 72 69 76 65 20 54 6f 6f 6c } //2 \PC Drive Tool
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 55 6c 74 69 6d 61 74 65 20 46 69 78 65 72 } //2 SOFTWARE\Ultimate Fixer
		$a_01_3 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 64 00 78 00 2e 00 64 00 6c 00 6c 00 } //1 C:\WINDOWS\sysdx.dll
		$a_01_4 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 6d 00 73 00 76 00 62 00 2e 00 64 00 6c 00 6c 00 } //1 C:\WINDOWS\msvb.dll
		$a_01_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 68 73 74 73 79 73 2e 64 6c 6c } //1 C:\WINDOWS\hstsys.dll
		$a_01_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 68 6f 73 74 63 74 72 6c 2e 64 6c 6c } //1 C:\WINDOWS\hostctrl.dll
		$a_01_7 = {53 00 68 00 65 00 6c 00 6c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 44 00 65 00 6c 00 61 00 79 00 4c 00 6f 00 61 00 64 00 } //10 ShellServiceObjectDelayLoad
		$a_01_8 = {48 54 54 50 43 6c 69 65 6e 74 00 } //10
		$a_00_9 = {73 6f 66 74 77 61 72 65 5c 70 72 6f 64 75 63 74 73 } //10 software\products
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_00_9  & 1)*10) >=36
 
}