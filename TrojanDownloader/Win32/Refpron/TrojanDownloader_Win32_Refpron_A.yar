
rule TrojanDownloader_Win32_Refpron_A{
	meta:
		description = "TrojanDownloader:Win32/Refpron.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 30 30 67 6c 65 61 64 73 65 72 76 65 72 2e 63 6f 6d 2f 6c 69 73 74 2e 74 78 74 } //01 00  http://www.g00gleadserver.com/list.txt
		$a_01_1 = {5b 25 73 5d 0d 0a 00 } //02 00 
		$a_03_2 = {68 e8 03 00 00 ff d6 53 53 53 53 57 ff 15 90 01 03 10 85 c0 74 ea 55 ff d6 55 ff d6 55 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}