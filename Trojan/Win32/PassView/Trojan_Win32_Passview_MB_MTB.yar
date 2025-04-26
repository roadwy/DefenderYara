
rule Trojan_Win32_Passview_MB_MTB{
	meta:
		description = "Trojan:Win32/Passview.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {89 47 0c 8b 4d f4 8b 07 89 0c b0 8b 75 0c 8b 4d e4 8b 7d f8 8a 01 88 45 fc 8b d7 8d 45 d0 e8 ?? ?? ?? ?? 8b 45 d0 8a 4d fc 88 0c 38 47 89 7d f8 89 5d e8 ff 45 f4 8b 45 f4 38 1c 30 0f 85 } //1
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_01_2 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
		$a_01_3 = {2f 64 65 6c 65 74 65 72 65 67 6b 65 79 } //1 /deleteregkey
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_5 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 UnmapViewOfFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}