
rule PWS_Win32_OnLineGames_CPN{
	meta:
		description = "PWS:Win32/OnLineGames.CPN,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_02_0 = {8b d8 85 db 74 90 01 01 68 90 01 03 00 53 e8 90 01 02 ff ff 89 c6 68 90 01 03 00 53 e8 90 01 02 ff ff 90 00 } //10
		$a_02_1 = {4e 76 53 79 73 5f 90 04 02 03 30 2d 39 2e 54 61 6f 90 00 } //1
		$a_02_2 = {4e 76 53 79 73 5f 90 04 02 03 30 2d 39 2e 53 79 73 90 00 } //1
		$a_00_3 = {4d 73 67 48 6f 6f 6b 4f 70 } //1 MsgHookOp
		$a_00_4 = {4d 73 67 48 6f 6f 6b 69 66 } //1 MsgHookif
		$a_02_5 = {4e 76 57 69 6e 5f 90 04 01 03 30 2d 39 2e 4c 73 74 90 00 } //1
		$a_02_6 = {4e 76 57 69 6e 5f 90 04 01 03 30 2d 39 2e 4a 6d 70 90 00 } //1
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_8 = {44 65 6c 65 74 65 46 69 6c 65 41 } //1 DeleteFileA
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=17
 
}