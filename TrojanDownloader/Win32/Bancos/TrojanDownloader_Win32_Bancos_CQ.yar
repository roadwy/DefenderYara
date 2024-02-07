
rule TrojanDownloader_Win32_Bancos_CQ{
	meta:
		description = "TrojanDownloader:Win32/Bancos.CQ,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 20 2d 6b 69 6c 6c 66 69 6c 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 67 62 70 6b 6d 2e 73 79 73 } //01 00  .exe -killfile C:\WINDOWS\system32\drivers\gbpkm.sys
		$a_01_1 = {2e 65 78 65 20 2d 6b 69 6c 6c 66 69 6c 65 20 43 3a 5c 41 72 71 75 69 76 7e 31 5c 47 62 50 6c 75 67 69 6e 5c 67 62 70 73 76 2e 65 78 65 } //01 00  .exe -killfile C:\Arquiv~1\GbPlugin\gbpsv.exe
		$a_01_2 = {2e 65 78 65 20 2d 6b 69 6c 6c 66 69 6c 65 20 43 3a 5c 41 72 71 75 69 76 7e 31 5c 47 62 50 6c 75 67 69 6e 5c 67 62 70 64 69 73 74 2e 64 6c 6c } //01 00  .exe -killfile C:\Arquiv~1\GbPlugin\gbpdist.dll
		$a_01_3 = {2e 65 78 65 20 2d 6b 69 6c 6c 66 69 6c 65 20 43 3a 5c 41 72 71 75 69 76 7e 31 5c 47 62 50 6c 75 67 69 6e 5c 67 62 69 65 68 2e 64 6c 6c } //02 00  .exe -killfile C:\Arquiv~1\GbPlugin\gbieh.dll
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 4c 6f 67 73 76 63 2e 62 61 74 } //02 00  C:\WINDOWS\System32\Logsvc.bat
		$a_01_5 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 50 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 64 65 6c 6f 6e 2e 74 78 74 } //00 00  C:\Arquivos de Programas\Internet Explorer\delon.txt
	condition:
		any of ($a_*)
 
}