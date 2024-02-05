
rule TrojanDownloader_Win32_Thoper_C{
	meta:
		description = "TrojanDownloader:Win32/Thoper.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 10 03 c6 8a 08 2a 4d 0c 32 4d 0c 02 4d 0c 88 08 } //01 00 
		$a_01_1 = {48 54 3a 20 73 65 6e 64 28 25 64 29 } //01 00 
		$a_01_2 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 2f 25 64 20 48 54 54 50 2f 31 2e 30 } //00 00 
	condition:
		any of ($a_*)
 
}