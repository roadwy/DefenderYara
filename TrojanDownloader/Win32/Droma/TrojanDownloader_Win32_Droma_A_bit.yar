
rule TrojanDownloader_Win32_Droma_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Droma.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 6c 00 61 00 67 00 5f 00 52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 5f 00 } //01 00 
		$a_01_1 = {31 71 61 7a 58 53 57 40 33 65 64 63 56 46 52 24 35 74 67 62 4e 48 59 } //01 00 
		$a_01_2 = {31 30 32 39 33 38 34 37 2d 35 2d 36 2d 44 6f 77 6e 6c 6f 61 64 26 25 64 2f } //01 00 
		$a_01_3 = {5c 63 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 } //00 00 
	condition:
		any of ($a_*)
 
}