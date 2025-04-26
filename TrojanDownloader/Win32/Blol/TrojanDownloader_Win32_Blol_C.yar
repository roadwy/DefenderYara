
rule TrojanDownloader_Win32_Blol_C{
	meta:
		description = "TrojanDownloader:Win32/Blol.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 b8 0b 00 00 e8 ?? ?? 00 00 6a 00 ff 75 ec e8 ?? ?? 00 00 68 85 00 00 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 } //2
		$a_03_1 = {74 07 6a 00 e8 ?? ?? 00 00 6a ?? 68 ?? ?? 40 00 6a ff 6a ff e8 ?? ?? ff ff 50 6a 18 68 ?? ?? 40 00 c7 45 a4 00 00 00 00 c7 45 a8 00 00 00 00 c7 45 ac 00 00 00 00 } //2
		$a_01_2 = {65 63 68 6f 20 6f 6c 68 61 20 3e 20 43 3a 5c 54 45 4d 50 5c 62 6c 6f 6c 6f 72 } //1 echo olha > C:\TEMP\blolor
		$a_01_3 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 66 20 2d 74 20 31 30 20 2d 63 20 22 45 72 72 6f 20 49 6e 74 65 72 6e 6f 20 64 6f 20 57 69 6e 64 6f 77 73 } //1 shutdown -r -f -t 10 -c "Erro Interno do Windows
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 65 72 } //1 MicrosoftOptimizationer
		$a_03_5 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 65 6e 20 5c 53 79 73 74 65 6d 33 32 5c 68 61 68 61 68 61 [0-05] 6a 75 6d 70 65 72 72 2e 65 78 65 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=5
 
}