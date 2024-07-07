
rule TrojanDownloader_Win32_Rochap_P{
	meta:
		description = "TrojanDownloader:Win32/Rochap.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 72 69 74 69 73 68 2e 64 6c 6c 00 62 65 73 74 6f 66 00 } //1
		$a_03_1 = {8b 45 ec e8 90 01 04 50 e8 90 01 04 50 e8 90 01 04 89 45 fc ff 75 f8 ff 75 f4 ff 55 fc 33 c0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}