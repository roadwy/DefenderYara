
rule TrojanDownloader_Win32_Brbank_A{
	meta:
		description = "TrojanDownloader:Win32/Brbank.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 74 61 75 61 70 6c 69 63 61 74 69 76 6f 2e 65 78 65 } //02 00 
		$a_03_1 = {31 c0 39 c2 74 0a 80 b0 90 01 04 08 40 eb 90 00 } //00 00 
		$a_00_2 = {7e 15 } //00 00 
	condition:
		any of ($a_*)
 
}