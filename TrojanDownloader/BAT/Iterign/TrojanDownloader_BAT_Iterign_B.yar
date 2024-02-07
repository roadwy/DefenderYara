
rule TrojanDownloader_BAT_Iterign_B{
	meta:
		description = "TrojanDownloader:BAT/Iterign.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 6b 00 69 00 63 00 6b 00 5f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  \kick_me.exe
		$a_01_1 = {5c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 6c 00 6e 00 6b 00 } //01 00  \Configuration.lnk
		$a_01_2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00 43 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 65 00 78 00 65 00 } //00 00  C:\Windows Update\Console Security.exe
	condition:
		any of ($a_*)
 
}