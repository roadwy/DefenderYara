
rule TrojanDownloader_Win32_Small_AIM{
	meta:
		description = "TrojanDownloader:Win32/Small.AIM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 39 39 39 39 39 39 39 39 39 39 39 2e 75 72 6c } //01 00 
		$a_01_1 = {74 61 7a 62 61 6f 2e 63 6f 6d } //01 00 
		$a_01_2 = {5c 66 69 65 2e 65 78 65 } //01 00 
		$a_01_3 = {25 73 5c 47 6f 6f 67 6c 65 25 63 25 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}