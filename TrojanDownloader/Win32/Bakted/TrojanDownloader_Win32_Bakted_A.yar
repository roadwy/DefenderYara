
rule TrojanDownloader_Win32_Bakted_A{
	meta:
		description = "TrojanDownloader:Win32/Bakted.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 25 73 2c 53 65 74 } //01 00  %s\rundll32.exe %s%s,Set
		$a_01_1 = {25 64 25 64 25 64 64 6f 6e 2e 64 6c 6c 00 00 00 64 65 6c 20 25 30 } //01 00 
		$a_01_2 = {64 2e 62 61 74 00 00 00 79 61 68 6f 6f 21 00 00 25 73 2c 53 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}