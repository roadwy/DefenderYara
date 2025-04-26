
rule TrojanDownloader_Win32_Banload_BEU{
	meta:
		description = "TrojanDownloader:Win32/Banload.BEU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 62 66 74 69 6e 73 6a 2e 73 79 73 20 26 65 63 68 6f 20 63 61 72 61 69 3e 3e 20 22 25 50 52 4f } //1 gbftinsj.sys &echo carai>> "%PRO
		$a_01_1 = {25 75 70 76 61 72 69 61 62 6c 65 25 } //1 %upvariable%
		$a_01_2 = {73 65 74 78 2e 65 78 65 20 55 50 4c 4b 56 41 52 49 41 42 4c 45 20 22 68 74 74 70 } //1 setx.exe UPLKVARIABLE "http
		$a_01_3 = {26 26 62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 61 25 52 41 4e 44 4f 4d 25 20 2f 44 6f 77 6e 6c 6f 61 64 20 2f 50 52 49 4f 52 49 54 59 20 48 49 47 48 20 68 74 74 70 } //1 &&bitsadmin /transfer a%RANDOM% /Download /PRIORITY HIGH http
		$a_01_4 = {47 62 50 6c 75 67 69 6e 5c 67 62 66 74 69 6e 33 32 2e 73 79 73 22 20 26 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 } //1 GbPlugin\gbftin32.sys" &shutdown /r /t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}