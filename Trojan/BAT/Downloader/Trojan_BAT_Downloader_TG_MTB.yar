
rule Trojan_BAT_Downloader_TG_MTB{
	meta:
		description = "Trojan:BAT/Downloader.TG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 65 79 64 2e 65 78 65 } //01 00  heyd.exe
		$a_81_1 = {54 72 79 20 61 20 64 69 66 66 65 72 65 6e 74 20 63 6f 6d 70 75 74 65 72 21 } //01 00  Try a different computer!
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 58 35 35 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 36 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 36 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 36 2e 70 64 62 } //01 00  C:\Users\X55\source\repos\WindowsFormsApp36\WindowsFormsApp36\obj\Release\WindowsFormsApp36.pdb
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_5 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //00 00  GetTempFileName
	condition:
		any of ($a_*)
 
}