
rule Trojan_BAT_SmallDownloader_EXPI_MTB{
	meta:
		description = "Trojan:BAT/SmallDownloader.EXPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_1 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_81_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_3 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_4 = {48 61 73 68 54 65 78 74 } //1 HashText
		$a_81_5 = {53 61 69 6e 74 53 70 6f 6f 66 65 72 20 7c 20 4c 6f 61 64 65 72 } //1 SaintSpoofer | Loader
		$a_81_6 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 74 69 61 67 6f 70 61 73 74 65 72 2f 73 70 6f 6f 66 65 72 2f 72 61 77 } //1 https://github.com/tiagopaster/spoofer/raw
		$a_81_7 = {53 61 69 6e 74 53 70 6f 6f 66 65 72 2e 70 64 62 } //1 SaintSpoofer.pdb
		$a_81_8 = {24 39 33 31 34 61 33 34 64 2d 65 61 66 30 2d 34 39 62 30 2d 62 65 62 63 2d 30 61 37 37 61 36 62 62 30 32 62 30 } //1 $9314a34d-eaf0-49b0-bebc-0a77a6bb02b0
		$a_81_9 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}