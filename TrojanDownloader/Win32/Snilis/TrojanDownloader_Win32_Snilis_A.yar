
rule TrojanDownloader_Win32_Snilis_A{
	meta:
		description = "TrojanDownloader:Win32/Snilis.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 58 ff fc 90 fc e0 6a ff fb 11 6c 54 ff 6c 58 ff fc a0 6c 54 ff f5 01 00 00 00 aa 71 54 ff 04 70 ff 67 4c ff 2b 00 } //1
		$a_01_1 = {2a 31 68 ff 32 20 00 60 ff 5c ff 58 ff 54 ff 50 ff 4c ff 48 ff 44 ff 40 ff 3c ff 38 ff 34 ff 30 ff 2c ff 28 ff 24 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}