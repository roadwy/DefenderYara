
rule TrojanDownloader_Win32_Coinminer_OS_bit{
	meta:
		description = "TrojanDownloader:Win32/Coinminer.OS!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 64 00 62 00 6c 00 6f 00 63 00 6b 00 2e 00 61 00 6b 00 6b 00 65 00 6c 00 73 00 2e 00 72 00 75 00 2f 00 90 02 10 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 25 73 69 74 65 25 2c 20 77 69 6e 68 6f 73 74 2e 65 78 65 } //01 00  URLDownloadToFile, %site%, winhost.exe
		$a_01_2 = {46 69 6c 65 53 65 74 41 74 74 72 69 62 2c 20 2b 48 2b 53 } //01 00  FileSetAttrib, +H+S
		$a_01_3 = {46 69 6c 65 43 72 65 61 74 65 44 69 72 2c 20 25 41 70 70 64 61 74 61 25 5c 53 68 65 6c 6c } //00 00  FileCreateDir, %Appdata%\Shell
	condition:
		any of ($a_*)
 
}