
rule Trojan_Win32_SysWiper_DE_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,59 00 59 00 0d 00 00 "
		
	strings :
		$a_03_0 = {48 89 4d b0 48 c7 45 b8 03 00 00 00 4c 8d 45 b0 8b d0 48 8d 4c 24 50 e8 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d c7 5a 00 00 48 89 4d b0 48 c7 45 b8 03 00 00 00 4c 8d 45 b0 8b d0 48 8d 4c 24 70 e8 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d a2 5a 00 00 48 89 4d b0 48 c7 45 b8 03 00 00 00 4c 8d 45 b0 8b d0 48 8d 4d } //50
		$a_01_1 = {4e 6f 74 20 72 75 6e 6e 69 6e 67 20 77 69 74 68 20 61 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 2e } //10 Not running with admin privileges.
		$a_01_2 = {52 75 6e 6e 69 6e 67 20 77 69 74 68 20 61 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 73 2e } //10 Running with admin privileges.
		$a_01_3 = {64 69 72 65 63 74 6f 72 79 5f 69 74 65 72 61 74 6f 72 3a 3a 6f 70 65 72 61 74 6f 72 2b 2b } //1 directory_iterator::operator++
		$a_01_4 = {72 65 63 75 72 73 69 76 65 5f 64 69 72 65 63 74 6f 72 79 5f 69 74 65 72 61 74 6f 72 3a 3a 72 65 63 75 72 73 69 76 65 5f 64 69 72 65 63 74 6f 72 79 5f 69 74 65 72 61 74 6f 72 } //1 recursive_directory_iterator::recursive_directory_iterator
		$a_01_5 = {4d 75 6c 74 69 42 79 74 65 54 6f 57 69 64 65 43 68 61 72 } //1 MultiByteToWideChar
		$a_01_6 = {57 69 64 65 43 68 61 72 54 6f 4d 75 6c 74 69 42 79 74 65 } //1 WideCharToMultiByte
		$a_01_7 = {6d 65 6d 6d 6f 76 65 } //1 memmove
		$a_01_8 = {6d 65 6d 63 70 79 } //1 memcpy
		$a_01_9 = {43 72 65 61 74 65 46 69 6c 65 32 } //10 CreateFile2
		$a_01_10 = {53 6c 65 65 70 } //1 Sleep
		$a_01_11 = {72 65 6d 6f 76 65 } //1 remove
		$a_01_12 = {73 74 61 74 75 73 } //1 status
	condition:
		((#a_03_0  & 1)*50+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*10+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=89
 
}