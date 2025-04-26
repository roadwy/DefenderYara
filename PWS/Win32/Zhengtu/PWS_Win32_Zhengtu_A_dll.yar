
rule PWS_Win32_Zhengtu_A_dll{
	meta:
		description = "PWS:Win32/Zhengtu.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0a 00 00 "
		
	strings :
		$a_00_0 = {7a 68 65 6e 67 74 75 } //10 zhengtu
		$a_00_1 = {06 00 00 00 26 55 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff 08 00 00 00 26 53 65 72 76 65 72 3d } //10
		$a_00_2 = {08 00 00 00 26 50 43 4e 61 6d 65 3d 00 00 00 00 ff ff ff ff 0b 00 00 00 26 50 43 45 64 69 74 69 6f 6e 3d 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b } //5
		$a_00_3 = {09 00 00 00 26 57 69 6e 4e 61 6d 65 3d 00 00 00 ff ff ff ff 0b 00 00 00 26 57 69 6e 42 61 6e 42 65 6e 3d 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b } //5
		$a_00_4 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_02_6 = {5f 44 4c 4c 2e 64 6c 6c [0-06] 48 6f 6f 6b } //1
		$a_00_7 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_00_8 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //1 GetKeyboardType
		$a_00_9 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=31
 
}