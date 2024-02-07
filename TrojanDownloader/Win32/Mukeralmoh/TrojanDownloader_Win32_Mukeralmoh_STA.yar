
rule TrojanDownloader_Win32_Mukeralmoh_STA{
	meta:
		description = "TrojanDownloader:Win32/Mukeralmoh.STA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 6c 41 75 74 6f 4f 70 65 6e 00 } //01 00 
		$a_01_1 = {7a 00 68 00 6f 00 6d 00 6c 00 61 00 2e 00 63 00 6f 00 6d 00 } //01 00  zhomla.com
		$a_01_2 = {25 00 50 00 55 00 42 00 4c 00 49 00 43 00 25 00 5c 00 73 00 6f 00 75 00 6e 00 64 00 6c 00 69 00 62 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //01 00  %PUBLIC%\soundlib64.exe
		$a_01_3 = {2f 00 64 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00 32 00 2e 00 78 00 6d 00 6c 00 } //00 00  /database_client2.xml
	condition:
		any of ($a_*)
 
}