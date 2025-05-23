
rule Trojan_Win32_Zlob_gen_A{
	meta:
		description = "Trojan:Win32/Zlob.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffac 00 ffffffab 00 10 00 00 "
		
	strings :
		$a_00_0 = {65 6d 6c 6b 64 76 6f 2e 44 4c 4c } //20 emlkdvo.DLL
		$a_00_1 = {46 6c 73 53 65 74 56 61 6c 75 65 } //1 FlsSetValue
		$a_00_2 = {46 49 6e 74 65 72 6c 6f 63 6b 65 64 50 6f 70 45 6e 74 72 79 53 4c 69 73 74 } //1 FInterlockedPopEntrySList
		$a_00_3 = {4d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 52 00 61 00 77 00 } //1 Module_Raw
		$a_00_4 = {48 00 4b 00 45 00 59 00 5f 00 43 00 4c 00 41 00 53 00 53 00 45 00 53 00 5f 00 52 00 4f 00 4f 00 54 00 } //1 HKEY_CLASSES_ROOT
		$a_00_5 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 } //1 HKEY_CURRENT_USER
		$a_00_6 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 } //1 HKEY_LOCAL_MACHINE
		$a_00_7 = {48 00 4b 00 45 00 59 00 5f 00 55 00 53 00 45 00 52 00 53 00 } //1 HKEY_USERS
		$a_00_8 = {48 00 4b 00 45 00 59 00 5f 00 50 00 45 00 52 00 46 00 4f 00 52 00 4d 00 41 00 4e 00 43 00 45 00 5f 00 44 00 41 00 54 00 41 00 } //1 HKEY_PERFORMANCE_DATA
		$a_00_9 = {48 00 4b 00 45 00 59 00 5f 00 44 00 59 00 4e 00 5f 00 44 00 41 00 54 00 41 00 } //1 HKEY_DYN_DATA
		$a_00_10 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 43 00 4f 00 4e 00 46 00 49 00 47 00 } //1 HKEY_CURRENT_CONFIG
		$a_00_11 = {5c 00 49 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 65 00 64 00 20 00 43 00 61 00 74 00 65 00 67 00 6f 00 72 00 69 00 65 00 73 00 } //1 \Implemented Categories
		$a_00_12 = {5c 00 52 00 65 00 71 00 75 00 69 00 72 00 65 00 64 00 20 00 43 00 61 00 74 00 65 00 67 00 6f 00 72 00 69 00 65 00 73 00 } //1 \Required Categories
		$a_00_13 = {65 00 6d 00 6c 00 6b 00 64 00 76 00 6f 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //20 emlkdvoTOOLBAR
		$a_00_14 = {54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 33 00 32 00 } //20 ToolbarWindow32
		$a_02_15 = {89 45 c0 8b 4d c0 83 79 18 08 72 0e 8b 55 c0 8b 42 04 89 85 ?? ?? ff ff eb 0c 8b 4d c0 83 c1 04 89 8d ?? ?? ff ff 6a 00 8d 55 fc 52 6a 00 68 06 00 02 00 6a 00 6a 00 6a 00 8b 85 ?? ?? ff ff 50 68 02 00 00 80 ff 15 04 f0 01 10 6a 00 6a 01 8d 4d e0 e8 ?? ca ff ff 68 ?? 00 02 10 8d 4d c4 51 e8 ?? ?? ff ff } //100
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*20+(#a_00_14  & 1)*20+(#a_02_15  & 1)*100) >=171
 
}