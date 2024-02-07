
rule TrojanDownloader_Win32_Agent_AAR{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 63 6f 2e 63 61 62 } //01 00  ico.cab
		$a_00_1 = {75 72 6c 2e 63 61 62 } //01 00  url.cab
		$a_00_2 = {5c 7a 73 2e 62 61 74 } //01 00  \zs.bat
		$a_02_3 = {75 6b 61 64 2e 63 6f 6d 90 02 04 2f 6b 69 6e 67 73 6f 66 74 2e 63 61 62 90 00 } //01 00 
		$a_02_4 = {63 68 61 74 5f 90 04 06 0a 30 31 32 33 34 35 36 37 38 39 2e 65 78 65 90 0a 40 00 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}