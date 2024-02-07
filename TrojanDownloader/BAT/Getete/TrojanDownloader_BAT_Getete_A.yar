
rule TrojanDownloader_BAT_Getete_A{
	meta:
		description = "TrojanDownloader:BAT/Getete.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 65 00 2e 00 74 00 74 00 2f 00 61 00 70 00 69 00 2f 00 31 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 90 01 0a 90 02 0a 2f 00 30 00 2f 00 62 00 6c 00 6f 00 62 00 3f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 90 00 } //05 00 
		$a_01_1 = {61 00 48 00 52 00 30 00 63 00 44 00 6f 00 76 00 4c 00 33 00 4e 00 6c 00 63 00 6e 00 59 00 79 00 4c 00 6e 00 4e 00 68 00 62 00 57 00 46 00 31 00 63 00 43 00 35 00 6a 00 62 00 32 00 30 00 76 00 5a 00 6d 00 6c 00 73 00 5a 00 58 00 } //01 00  aHR0cDovL3NlcnYyLnNhbWF1cC5jb20vZmlsZX
		$a_03_2 = {5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 90 01 01 5c 50 72 6f 6a 65 63 74 73 5c 90 00 } //01 00 
		$a_01_3 = {5c 44 65 73 6b 74 6f 70 5c 74 61 6e 67 6f 5c 74 61 6e 67 6f 5c } //01 00  \Desktop\tango\tango\
		$a_01_4 = {5c 44 65 73 6b 74 6f 70 5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 64 6f 77 6e 6c 6f 61 64 65 72 5c } //01 00  \Desktop\downloader\downloader\
		$a_01_5 = {5c 44 65 73 6b 74 6f 70 5c 70 72 6f 6a 65 63 74 5c 44 6c 6c 53 65 72 5c 53 65 72 76 69 63 65 5c } //00 00  \Desktop\project\DllSer\Service\
	condition:
		any of ($a_*)
 
}