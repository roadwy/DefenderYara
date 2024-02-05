
rule TrojanDownloader_Win32_Vaprop_A{
	meta:
		description = "TrojanDownloader:Win32/Vaprop.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 36 37 25 36 66 25 32 65 25 36 34 25 36 38 25 37 33 25 36 39 25 37 34 25 36 35 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 36 37 25 36 46 2e 25 36 34 25 36 38 25 37 33 25 36 39 25 37 34 25 36 35 } //0a 00 
		$a_01_2 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //00 00 
	condition:
		any of ($a_*)
 
}