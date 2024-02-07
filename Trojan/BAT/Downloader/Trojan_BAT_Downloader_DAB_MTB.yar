
rule Trojan_BAT_Downloader_DAB_MTB{
	meta:
		description = "Trojan:BAT/Downloader.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 33 31 2e 65 78 65 } //01 00  C:\ProgramData\131.exe
		$a_01_1 = {24 37 30 31 38 32 38 37 37 2d 31 35 31 38 2d 34 66 34 65 2d 39 39 64 36 2d 63 62 33 38 63 63 65 64 34 63 65 38 } //01 00  $70182877-1518-4f4e-99d6-cb38cced4ce8
		$a_81_2 = {68 74 74 70 3a 2f 2f 73 68 65 72 65 6e 63 65 2e 72 75 2f 31 33 31 2e 65 78 65 } //01 00  http://sherence.ru/131.exe
		$a_01_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 2e 65 78 65 } //01 00  WindowsFormsApp2.exe
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  CheckRemoteDebuggerPresent
	condition:
		any of ($a_*)
 
}