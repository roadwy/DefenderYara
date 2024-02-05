
rule TrojanDownloader_Win32_Stantinko_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Stantinko.A!MTB,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 53 42 30 5f 49 6e 69 74 } //01 00 
		$a_01_1 = {43 48 45 43 4b 4d 41 54 45 } //01 00 
		$a_01_2 = {32 30 30 34 2e 44 4c 4c } //01 00 
		$a_01_3 = {32 00 65 00 64 00 6b 00 6c 00 72 00 65 00 6c 00 2e 00 33 00 6c 00 6e 00 } //01 00 
		$a_01_4 = {3a 5c 54 68 65 6d 65 20 45 6e 67 69 6e 65 20 53 65 72 76 69 63 65 5c 52 65 6c 65 61 73 65 5c 34 34 2c 39 30 } //00 00 
		$a_01_5 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}