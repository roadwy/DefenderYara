
rule TrojanDownloader_Win32_Banload_AZO{
	meta:
		description = "TrojanDownloader:Win32/Banload.AZO,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4a 61 76 61 63 68 6b 2e 63 70 6c } //01 00  rundll32.exe shell32.dll,Control_RunDLL C:\ProgramData\Javachk.cpl
		$a_01_1 = {61 62 61 69 78 6f 75 20 2d 20 47 65 74 49 6e 65 74 46 69 6c 65 } //01 00  abaixou - GetInetFile
		$a_01_2 = {61 62 61 69 78 6f 75 20 2d 20 44 6f 44 6f 77 6e 6c 6f 61 64 } //01 00  abaixou - DoDownload
		$a_01_3 = {41 63 68 6f 75 20 61 20 70 61 67 69 6e 61 20 2d } //01 00  Achou a pagina -
		$a_01_4 = {72 65 67 69 63 70 6c 20 2d 20 74 72 79 } //00 00  regicpl - try
		$a_01_5 = {00 80 10 00 00 } //b4 35 
	condition:
		any of ($a_*)
 
}