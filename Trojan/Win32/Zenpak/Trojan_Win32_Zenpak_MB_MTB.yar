
rule Trojan_Win32_Zenpak_MB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 31 f6 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 3d 00 00 00 00 89 45 f4 89 4d f0 89 55 ec 89 75 e8 74 1e 8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 } //10
		$a_01_1 = {0b 01 09 07 00 20 00 00 00 70 12 00 00 02 00 00 e8 11 00 00 00 10 00 00 00 30 } //5
		$a_01_2 = {49 73 57 69 6e 45 76 65 6e 74 48 6f 6f 6b 49 6e 73 74 61 6c 6c 65 64 } //1 IsWinEventHookInstalled
		$a_01_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_01_4 = {46 72 65 65 43 72 65 64 65 6e 74 69 61 6c 73 48 61 6e 64 6c 65 } //1 FreeCredentialsHandle
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}