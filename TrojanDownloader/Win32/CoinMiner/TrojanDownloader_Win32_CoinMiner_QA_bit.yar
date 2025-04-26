
rule TrojanDownloader_Win32_CoinMiner_QA_bit{
	meta:
		description = "TrojanDownloader:Win32/CoinMiner.QA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 00 35 00 39 00 2e 00 32 00 30 00 33 00 2e 00 33 00 37 00 2e 00 31 00 31 00 30 00 2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 } //1 159.203.37.110/config/files/
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}