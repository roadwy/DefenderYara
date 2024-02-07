
rule TrojanDownloader_Win32_Agent_TS{
	meta:
		description = "TrojanDownloader:Win32/Agent.TS,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 61 62 63 2d 5f 2d 63 62 61 7d } //01 00  {abc-_-cba}
		$a_01_1 = {53 65 72 76 65 72 5f 43 72 61 63 6b 2e 72 61 72 } //01 00  Server_Crack.rar
		$a_01_2 = {5c 57 69 6e 48 25 63 25 63 25 63 33 32 2e 65 78 65 } //01 00  \WinH%c%c%c32.exe
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 37 72 61 72 5c } //00 00  C:\Program Files\7rar\
	condition:
		any of ($a_*)
 
}