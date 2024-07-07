
rule PWS_Win32_OnLineGames_FKW{
	meta:
		description = "PWS:Win32/OnLineGames.FKW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_2 = {72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 } //1 realmlist.wtf
		$a_00_3 = {2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 .worldofwarcraft.com
		$a_00_4 = {2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d } //1 .wowchina.com
		$a_00_5 = {48 6f 6f 6b 2e 64 6c 6c } //1 Hook.dll
		$a_00_6 = {6b 73 48 6f 6f 6b 77 6f } //1 ksHookwo
		$a_00_7 = {74 7a 48 6f 6f 6b 77 6f } //1 tzHookwo
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_9 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}