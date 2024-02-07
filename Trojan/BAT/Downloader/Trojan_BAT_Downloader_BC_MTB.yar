
rule Trojan_BAT_Downloader_BC_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //01 00  https://cdn.discordapp.com/attachments
		$a_01_1 = {45 72 72 6f 72 2d 4c 6f 67 2e 65 78 65 } //01 00  Error-Log.exe
		$a_01_2 = {43 3a 5c 56 6f 6e 65 78 5c 45 72 72 6f 72 4c 6f 67 2e 65 78 65 } //01 00  C:\Vonex\ErrorLog.exe
		$a_81_3 = {56 6f 6e 65 78 2e 78 79 7a } //01 00  Vonex.xyz
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 53 65 6e 74 69 65 6c 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 56 6f 6e 65 78 2d 4c 6f 61 64 65 72 2d 43 6f 6e 73 6f 6c 65 5c 56 6f 6e 65 78 2d 4c 6f 61 64 65 72 2d 43 6f 6e 73 6f 6c 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 56 6f 6e 65 78 2d 4c 6f 61 64 65 72 2d 43 6f 6e 73 6f 6c 65 2e 70 64 62 } //01 00  C:\Users\Sentiel\source\repos\Vonex-Loader-Console\Vonex-Loader-Console\obj\Debug\Vonex-Loader-Console.pdb
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_6 = {43 3a 5c 56 6f 6e 65 78 5c } //00 00  C:\Vonex\
	condition:
		any of ($a_*)
 
}