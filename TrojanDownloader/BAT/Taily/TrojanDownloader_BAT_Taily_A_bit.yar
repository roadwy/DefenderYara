
rule TrojanDownloader_BAT_Taily_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Taily.A!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 \Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {72 00 67 00 68 00 6f 00 2e 00 73 00 74 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 } //1 rgho.st/download/
		$a_01_2 = {69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 iplogger.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}