
rule TrojanDownloader_Win32_Kredak{
	meta:
		description = "TrojanDownloader:Win32/Kredak,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 68 61 69 64 72 69 76 65 72 2e 6e 65 74 } //02 00 
		$a_01_1 = {25 73 5c 6f 2e 74 78 74 } //02 00 
		$a_01_2 = {25 73 2f 68 5f 76 2e 68 74 6d 6c } //02 00 
		$a_01_3 = {5b 41 4b 45 44 21 5d } //00 00 
	condition:
		any of ($a_*)
 
}