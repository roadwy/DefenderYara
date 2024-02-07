
rule TrojanDownloader_Win32_Wysotot_A{
	meta:
		description = "TrojanDownloader:Win32/Wysotot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {eb 0f 81 7d f8 50 4b 01 02 b8 99 ff ff ff 0f 45 d8 8b 3e 8d 55 f8 8b cf e8 } //01 00 
		$a_81_1 = {2f 44 50 72 6f 74 65 63 74 2e 65 78 65 } //01 00  /DProtect.exe
		$a_81_2 = {2f 65 47 64 70 53 76 63 2e 65 78 65 } //00 00  /eGdpSvc.exe
	condition:
		any of ($a_*)
 
}