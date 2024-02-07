
rule TrojanDownloader_Win32_Inservice{
	meta:
		description = "TrojanDownloader:Win32/Inservice,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 6c 65 78 63 61 72 73 2e 63 6f 6d } //01 00  dalexcars.com
		$a_01_1 = {47 45 54 20 2f 69 6e 74 65 72 63 6f 6f 6c 65 72 } //01 00  GET /intercooler
		$a_01_2 = {48 6f 73 74 3a 20 77 77 77 2e } //01 00  Host: www.
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 31 2d } //01 00  User-Agent: Mozilla/4.0 (compatible; 1-
		$a_01_4 = {31 39 32 2e 00 } //01 00 
		$a_01_5 = {2f 75 73 65 72 73 2f 6d 75 6c 65 7a 2f } //01 00  /users/mulez/
		$a_01_6 = {25 73 5c 25 73 25 64 2e 65 78 65 } //01 00  %s\%s%d.exe
		$a_01_7 = {69 6e 74 65 72 63 6f 6f 6c 65 72 } //01 00  intercooler
		$a_01_8 = {70 6f 6e 79 } //01 00  pony
		$a_01_9 = {69 6e 65 74 5f 61 64 64 72 } //01 00  inet_addr
		$a_01_10 = {73 6f 63 6b 65 74 } //01 00  socket
		$a_01_11 = {73 74 72 74 6f 6b } //00 00  strtok
	condition:
		any of ($a_*)
 
}