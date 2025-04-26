
rule Trojan_Win32_Stolpen_D{
	meta:
		description = "Trojan:Win32/Stolpen.D,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 75 73 65 72 20 25 73 20 53 65 63 75 72 69 74 79 31 32 31 35 21 20 2f 61 64 64 } //1 net user %s Security1215! /add
		$a_01_1 = {6e 65 74 20 75 73 65 72 20 25 73 20 77 61 6c 64 6f 31 32 31 35 21 20 2f 61 64 64 } //1 net user %s waldo1215! /add
		$a_01_2 = {2f 45 58 50 49 52 45 53 3a 4e 45 56 45 52 20 2f 41 63 74 69 76 65 3a 59 45 53 26 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 75 73 65 72 73 20 25 73 20 2f 64 65 6c 65 74 65 26 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 25 73 20 2f 61 64 64 } //2 /EXPIRES:NEVER /Active:YES&net localgroup users %s /delete&net localgroup Administrators %s /add
		$a_80_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 } //SYSTEM\CurrentControlSet\Control\Terminal Server  2
		$a_80_4 = {66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //fDenyTSConnections  2
		$a_80_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 53 70 65 63 69 61 6c 41 63 63 6f 75 6e 74 73 5c 55 73 65 72 4c 69 73 74 } //SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList  2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=9
 
}