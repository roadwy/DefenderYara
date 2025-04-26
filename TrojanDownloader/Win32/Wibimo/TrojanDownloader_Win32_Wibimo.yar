
rule TrojanDownloader_Win32_Wibimo{
	meta:
		description = "TrojanDownloader:Win32/Wibimo,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 02 c6 01 6d c6 41 01 73 5e a1 ?? ?? ?? ?? 85 c0 75 0e 0f 31 03 c2 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 c3 9e 26 00 } //3
		$a_00_1 = {47 23 f8 8d b4 3d f0 fe ff ff 8a 16 0f b6 ca 03 4d f4 23 c8 89 4d f4 8d 8c 0d f0 fe ff ff 8a 19 88 11 8b 55 08 88 1e 0f b6 09 8b 75 f8 0f b6 db 03 cb 23 c8 8a 8c 0d f0 fe ff ff 03 d6 30 0a 46 3b 75 0c 89 75 f8 7c b8 } //3
		$a_00_2 = {47 6c 6f 62 61 6c 5c 73 70 5f 72 75 6e 6e 65 64 } //1 Global\sp_runned
		$a_00_3 = {61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 67 72 61 6d 3d 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 22 } //1 action=allow program="%windir%\system32\rundll32.exe"
		$a_01_4 = {4e 45 54 53 48 20 61 64 76 66 69 72 65 77 61 6c 6c 20 46 49 52 45 57 41 4c 4c 20 61 64 64 20 72 75 6c 65 } //1 NETSH advfirewall FIREWALL add rule
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}