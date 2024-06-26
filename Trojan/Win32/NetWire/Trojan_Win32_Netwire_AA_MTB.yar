
rule Trojan_Win32_Netwire_AA_MTB{
	meta:
		description = "Trojan:Win32/Netwire.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 11 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 6e 61 6d 65 73 2e 74 78 74 } //0a 00  filenames.txt
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } //01 00  SOFTWARE\NetWire
		$a_81_2 = {68 6f 73 74 6e 61 6d 65 } //01 00  hostname
		$a_81_3 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //01 00  encryptedUsername
		$a_81_4 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //05 00  encryptedPassword
		$a_81_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //05 00  Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook
		$a_81_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 31 36 2e 30 5c 4f 75 74 6c 6f 6f 6b 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //05 00  Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook
		$a_81_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //05 00  Software\Microsoft\Internet Explorer\IntelliForms\Storage2
		$a_81_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_81_9 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //05 00  encrypted_key
		$a_81_10 = {25 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //05 00  %s\Google\Chrome\User Data\Default\Login Data
		$a_81_11 = {25 73 5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //05 00  %s\Chromium\User Data\Default\Login Data
		$a_81_12 = {25 73 5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //05 00  %s\Comodo\Dragon\User Data\Default\Login Data
		$a_81_13 = {25 73 5c 59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //05 00  %s\Yandex\YandexBrowser\User Data\Default\Login Data
		$a_81_14 = {25 73 5c 42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //05 00  %s\BraveSoftware\Brave-Browser\User Data\Default\Login Data
		$a_81_15 = {25 73 5c 33 36 30 43 68 72 6f 6d 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  %s\360Chrome\Chrome\User Data\Default\Login Data
		$a_81_16 = {48 6f 73 74 2e 65 78 65 } //00 00  Host.exe
		$a_00_17 = {5d 04 00 00 3e ff 03 80 5c 31 00 00 3f ff 03 80 00 00 01 00 32 00 1b 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 47 61 6e 64 63 72 61 62 2e 4e 21 4d 54 42 00 00 01 40 05 82 70 00 04 } //00 78 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Netwire_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Netwire.AA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ca 88 55 ff 80 75 ff dc 8b da c1 e9 08 8b c2 c1 eb 10 80 f1 24 c1 e8 18 80 f3 35 34 37 80 f9 14 75 0f 80 fb 01 75 0a 84 c0 75 06 80 7d ff e9 74 03 42 eb cb } //01 00 
		$a_01_1 = {8b c2 8d 8d 08 fd ff ff 83 e0 03 03 ca 83 c2 06 0f b6 44 05 f8 30 01 8d 04 0e 83 e0 03 0f b6 44 05 f8 30 41 01 8d 04 0f 83 e0 03 0f b6 44 05 f8 30 41 02 8d 04 0b 83 e0 03 0f b6 44 05 f8 30 41 03 8b 45 f4 03 c1 83 e0 03 0f b6 44 05 f8 30 41 04 8b 45 f0 03 c1 83 e0 03 0f b6 44 05 f8 30 41 05 81 fa e2 02 00 00 72 97 } //00 00 
	condition:
		any of ($a_*)
 
}