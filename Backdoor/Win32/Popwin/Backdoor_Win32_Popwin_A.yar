
rule Backdoor_Win32_Popwin_A{
	meta:
		description = "Backdoor:Win32/Popwin.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 09 00 00 "
		
	strings :
		$a_00_0 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //1 EnumProcessModules
		$a_00_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_00_2 = {4b 69 6c 6c 4d 65 2e 62 61 74 } //1 KillMe.bat
		$a_00_3 = {50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 Product_Notification
		$a_00_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 } //1 SYSTEM\CurrentControlSet\Services
		$a_00_5 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_6 = {67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c } //1 goto selfkill
		$a_00_7 = {70 69 6e 67 20 2d 6e 20 34 35 20 6c 6f 63 61 6c 68 6f 73 74 } //1 ping -n 45 localhost
		$a_02_8 = {be 00 10 40 00 b9 04 00 00 00 8b f9 81 fe ?? ?? ?? ?? 7f 10 ac 47 04 18 2c 02 73 f0 29 3e 03 f1 03 f9 eb e8 ba 00 00 40 00 8d b2 ?? ?? 00 00 8b 46 0c 85 c0 [0-06] 03 c2 8b 7e 10 8b 1e 85 db 75 02 8b df 03 da 03 fa 52 57 50 ff 15 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*5) >=10
 
}