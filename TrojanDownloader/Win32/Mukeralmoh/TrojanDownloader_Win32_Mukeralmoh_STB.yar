
rule TrojanDownloader_Win32_Mukeralmoh_STB{
	meta:
		description = "TrojanDownloader:Win32/Mukeralmoh.STB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 6c 41 75 74 6f 4f 70 65 6e 00 } //01 00 
		$a_01_1 = {66 00 6c 00 69 00 63 00 6b 00 72 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 75 00 64 00 69 00 74 00 62 00 6c 00 6f 00 67 00 73 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_01_2 = {61 00 70 00 70 00 6c 00 69 00 62 00 2e 00 68 00 74 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}