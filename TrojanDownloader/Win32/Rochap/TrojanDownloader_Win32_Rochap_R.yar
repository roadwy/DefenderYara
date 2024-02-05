
rule TrojanDownloader_Win32_Rochap_R{
	meta:
		description = "TrojanDownloader:Win32/Rochap.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6c 6c 2e 64 6c 6c 00 72 6f 64 61 72 } //01 00 
		$a_02_1 = {89 45 fc ff 75 90 01 01 ff 75 90 02 0e ff 55 90 01 01 33 c0 5a 59 59 64 89 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}