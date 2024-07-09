
rule Trojan_Win32_Abndog_A{
	meta:
		description = "Trojan:Win32/Abndog.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 38 5b 01 00 52 ff d6 68 c8 49 00 00 ff 15 ?? ?? ?? ?? 8d 44 24 18 45 50 68 ?? ?? ?? ?? 53 83 c7 04 } //10
		$a_00_1 = {48 6f 6f 6b 4c 65 61 76 65 00 00 00 48 6f 6f 6b 45 6e 74 65 72 00 00 00 44 4c 4c 00 48 4f 4f 4b 00 00 00 00 25 73 5c 25 30 38 58 2e 64 6c 6c 00 5f 54 48 49 } //1
		$a_00_2 = {25 73 5c 70 61 63 6b 5f 25 64 2e 65 78 65 } //1 %s\pack_%d.exe
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}
rule Trojan_Win32_Abndog_A_2{
	meta:
		description = "Trojan:Win32/Abndog.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {85 f6 74 37 80 3e 90 75 32 80 7e 01 60 75 2c 80 7e 02 e9 75 26 8b 46 03 8d 44 30 07 8d 70 0a 56 ff d7 84 c0 74 15 80 3e 74 75 10 6a 01 8d 45 ec 50 56 } //10
		$a_01_1 = {81 c7 e9 1c 00 00 57 ff d6 84 c0 74 14 80 3f 75 75 0f 6a 01 8d 85 fc fd ff ff 50 57 e8 } //10
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 42 00 41 00 5f 00 53 00 4f 00 46 00 54 00 } //1 \Device\NBA_SOFT
		$a_00_3 = {4d 6d 49 73 41 64 64 72 65 73 73 56 61 6c 69 64 } //1 MmIsAddressValid
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}