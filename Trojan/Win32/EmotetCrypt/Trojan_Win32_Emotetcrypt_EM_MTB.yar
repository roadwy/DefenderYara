
rule Trojan_Win32_Emotetcrypt_EM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {4d 66 63 54 54 54 } //1 MfcTTT
		$a_81_1 = {4c 61 79 76 58 42 63 4f 70 70 64 67 7a 43 67 6e 6e 63 41 } //1 LayvXBcOppdgzCgnncA
		$a_81_2 = {4d 6f 76 65 48 69 73 2e 74 78 74 } //1 MoveHis.txt
		$a_81_3 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_81_4 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 NoRecentDocsHistory
		$a_81_5 = {52 65 73 74 72 69 63 74 52 75 6e } //1 RestrictRun
		$a_81_6 = {4e 6f 44 72 69 76 65 73 } //1 NoDrives
		$a_81_7 = {4e 6f 43 6c 6f 73 65 } //1 NoClose
		$a_81_8 = {4e 6f 52 75 6e } //1 NoRun
		$a_81_9 = {47 61 6d 65 20 4f 76 65 72 21 } //1 Game Over!
		$a_81_10 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 ShellExecuteW
		$a_81_11 = {47 65 74 46 69 6c 65 54 79 70 65 } //1 GetFileType
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}