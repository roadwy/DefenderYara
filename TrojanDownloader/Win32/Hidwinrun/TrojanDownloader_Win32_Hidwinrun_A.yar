
rule TrojanDownloader_Win32_Hidwinrun_A{
	meta:
		description = "TrojanDownloader:Win32/Hidwinrun.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 48 52 55 4e 56 45 52 00 68 74 74 70 3a 2f 2f } //01 00  䠀啒噎剅栀瑴㩰⼯
		$a_01_1 = {00 48 54 54 50 47 45 54 44 41 54 41 00 68 74 74 70 3a 2f 2f } //01 00  䠀呔䝐呅䅄䅔栀瑴㩰⼯
		$a_01_2 = {25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 } //01 00  %02x%02x%02x%02x%02x%02x
		$a_01_3 = {25 73 5c 48 69 64 65 49 6e 73 74 61 6c 6c 65 72 5f 75 70 25 64 2e 65 78 65 00 00 00 53 6f 66 74 77 61 72 65 5c 25 73 } //01 00 
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}