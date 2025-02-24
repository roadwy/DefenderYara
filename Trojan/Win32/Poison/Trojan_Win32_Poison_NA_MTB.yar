
rule Trojan_Win32_Poison_NA_MTB{
	meta:
		description = "Trojan:Win32/Poison.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 } //2
		$a_01_1 = {4e 81 ce 00 ff ff ff 46 8a 17 8b 44 b4 14 88 54 24 10 89 07 8b 54 24 10 83 c7 04 81 e2 ff 00 00 00 41 81 f9 00 01 00 00 } //1
		$a_81_2 = {43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 Chrome\User Data\Default\Login Data
		$a_81_3 = {5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 \explorer.exe
		$a_81_4 = {4f 75 74 6c 6f 6f 6b 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //1 Outlook\Profiles\Outlook
		$a_81_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_6 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_81_7 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 logins.json
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}