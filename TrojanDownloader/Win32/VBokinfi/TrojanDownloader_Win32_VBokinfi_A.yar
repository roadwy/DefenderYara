
rule TrojanDownloader_Win32_VBokinfi_A{
	meta:
		description = "TrojanDownloader:Win32/VBokinfi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 74 00 70 00 2e 00 6f 00 6b 00 69 00 6e 00 66 00 69 00 6e 00 69 00 74 00 79 00 6f 00 6b 00 } //01 00 
		$a_01_1 = {66 00 75 00 63 00 6b 00 31 00 30 00 } //01 00 
		$a_01_2 = {62 00 61 00 6e 00 2e 00 7a 00 69 00 70 00 } //01 00 
		$a_03_3 = {63 00 65 00 74 00 2e 00 65 00 78 00 65 00 90 02 10 5c 00 43 00 65 00 74 00 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 db 
	condition:
		any of ($a_*)
 
}