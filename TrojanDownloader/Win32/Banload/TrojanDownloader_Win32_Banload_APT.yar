
rule TrojanDownloader_Win32_Banload_APT{
	meta:
		description = "TrojanDownloader:Win32/Banload.APT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 72 5b 65 5d 67 7e 20 5b 61 5d 64 5b 64 7e 20 5b } //01 00 
		$a_01_1 = {7e 52 5d 75 7e 6e 5e 44 7e 4c 5e 4c 5e 33 5d 32 5d } //01 00 
		$a_01_2 = {5e 68 7e 74 5b 74 7e 70 7e 3a 5d 2f 7e 2f 7e } //01 00 
		$a_01_3 = {5b 2e 5d 63 5d 70 7e 6c 5b } //01 00 
		$a_01_4 = {7e 41 5d 76 5b 69 7e 72 7e 61 } //01 00 
		$a_01_5 = {5b 41 5e 76 7e 67 5d 54 5e 72 5d 61 5b 79 } //00 00 
	condition:
		any of ($a_*)
 
}