
rule TrojanDownloader_Win32_Banload_AKW{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 68 6f 77 6a 61 70 61 6f 2e 68 75 74 32 2e 72 75 2f 6d 6f 64 75 6c 6f 61 2e 6a 70 67 } //01 00  http://showjapao.hut2.ru/moduloa.jpg
		$a_01_1 = {62 72 61 73 69 6c 77 69 6e 77 6f 73 31 2e 65 78 65 } //01 00  brasilwinwos1.exe
		$a_01_2 = {54 61 73 6b 62 61 72 43 72 65 61 74 65 64 } //01 00  TaskbarCreated
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //00 00  C:\ProgramData\
	condition:
		any of ($a_*)
 
}