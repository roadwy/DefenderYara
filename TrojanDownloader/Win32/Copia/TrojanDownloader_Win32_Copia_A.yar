
rule TrojanDownloader_Win32_Copia_A{
	meta:
		description = "TrojanDownloader:Win32/Copia.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 63 00 6f 00 70 00 69 00 61 00 5f 00 62 00 68 00 6f 00 5c 00 } //01 00  :\copia_bho\
		$a_01_1 = {41 00 50 00 49 00 2d 00 47 00 75 00 69 00 64 00 65 00 20 00 74 00 65 00 73 00 74 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //01 00  API-Guide test program
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 } //01 00 
		$a_01_3 = {32 2e 30 33 00 55 50 58 21 } //00 00 
	condition:
		any of ($a_*)
 
}