
rule TrojanDownloader_Win32_Carberp_J{
	meta:
		description = "TrojanDownloader:Win32/Carberp.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 73 53 43 4d 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {47 6f 6f 67 6c 65 55 70 64 61 74 65 42 65 74 61 2e 65 78 65 20 2f 73 76 63 } //01 00  GoogleUpdateBeta.exe /svc
		$a_01_2 = {47 6f 6f 67 6c 65 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 00 49 6e 73 74 61 6c 6c 00 53 74 61 72 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}