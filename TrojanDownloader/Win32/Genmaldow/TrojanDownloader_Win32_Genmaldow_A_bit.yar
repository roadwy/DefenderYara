
rule TrojanDownloader_Win32_Genmaldow_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Genmaldow.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6d 64 20 46 69 6c 65 73 5c 90 02 10 2e 70 6e 67 90 00 } //01 00 
		$a_03_1 = {69 6d 67 2e 73 79 75 61 6e 2e 6e 65 74 2f 66 6f 72 75 6d 2f 90 02 40 2e 6a 70 67 90 00 } //01 00 
		$a_01_2 = {4d 79 41 70 70 42 79 4d 75 6c 69 6e 42 } //01 00 
		$a_01_3 = {45 78 65 50 72 6f 63 65 73 73 74 65 73 74 } //01 00 
		$a_01_4 = {73 65 72 76 65 72 2e 64 61 74 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}