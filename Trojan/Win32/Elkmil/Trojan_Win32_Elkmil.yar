
rule Trojan_Win32_Elkmil{
	meta:
		description = "Trojan:Win32/Elkmil,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {47 00 4f 00 54 00 4f 00 20 00 53 00 54 00 41 00 52 00 54 00 00 00 1a 00 00 00 5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //2
		$a_00_1 = {5b 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 48 00 69 00 64 00 64 00 65 00 6e 00 5d 00 } //1 [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden]
		$a_00_2 = {72 00 65 00 67 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 20 00 } //1 regedit.exe /s 
		$a_03_3 = {c7 45 fc 33 00 00 00 c7 85 58 ff ff ff ?? ?? ?? ?? c7 85 50 ff ff ff 08 00 00 00 8d 95 50 ff ff ff 8d 8d 60 ff ff ff ff 15 ?? ?? ?? ?? 6a 00 8d 8d 60 ff ff ff 51 ff 15 } //3
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*3) >=4
 
}