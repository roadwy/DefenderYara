
rule TrojanSpy_Win32_Rukhami_S{
	meta:
		description = "TrojanSpy:Win32/Rukhami.S,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 6f 72 72 65 6e 74 73 20 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00  Torrents Downloader
		$a_01_1 = {61 64 75 6c 74 68 75 62 6e 65 77 2e 63 6c 75 62 } //01 00  adulthubnew.club
		$a_01_2 = {70 61 79 6c 6f 61 64 } //00 00  payload
	condition:
		any of ($a_*)
 
}