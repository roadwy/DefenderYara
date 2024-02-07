
rule TrojanDownloader_BAT_Crydap_A{
	meta:
		description = "TrojanDownloader:BAT/Crydap.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 64 00 43 00 5f 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  PadC_Downloader.exe
		$a_01_1 = {50 61 64 43 5f 44 6f 77 6e 6c 6f 61 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  PadC_Downloader.Properties
		$a_01_2 = {24 39 63 38 66 65 37 32 61 2d 62 30 31 30 2d 34 61 30 61 2d 61 38 34 33 2d 39 30 34 32 30 38 32 31 62 33 62 62 00 } //01 00  㤤㡣敦㈷ⵡぢ〱㐭ちⵡ㡡㌴㤭㐰〲㈸戱戳b
		$a_01_3 = {5c 50 72 6f 6a 65 63 74 73 5c 50 44 46 5c 50 61 64 43 5f 44 6f 77 6e 6c 6f 61 64 65 72 5c 62 69 6e 5c 44 65 62 75 67 5c 4f 62 66 75 73 63 61 74 65 64 5c 50 61 64 43 5f 44 6f 77 6e 6c 6f 61 64 65 72 2e 70 64 62 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}