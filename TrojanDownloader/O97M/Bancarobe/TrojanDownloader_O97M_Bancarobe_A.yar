
rule TrojanDownloader_O97M_Bancarobe_A{
	meta:
		description = "TrojanDownloader:O97M/Bancarobe.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {28 45 6e 76 69 72 6f 6e 28 22 61 70 22 20 26 } //01 00  (Environ("ap" &
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 30 26 2c 20 52 65 70 6c 61 63 65 28 22 68 } //01 00  URLDownloadToFileA 0&, Replace("h
		$a_00_2 = {26 20 22 2e 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 22 29 } //01 00  & "." & StrReverse("exe")
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c 20 53 74 72 50 74 72 28 } //00 00  ShellExecuteW 0&, StrPtr("Open"), StrPtr(
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}