
rule TrojanDownloader_BAT_Banload_N{
	meta:
		description = "TrojanDownloader:BAT/Banload.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 90 02 0a 68 00 74 00 74 00 70 00 90 00 } //01 00 
		$a_00_1 = {5c 42 61 6e 6b 73 5c 4c 6f 61 64 65 72 73 } //00 00  \Banks\Loaders
		$a_00_2 = {78 1d } //01 00  ᵸ
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Banload_N_2{
	meta:
		description = "TrojanDownloader:BAT/Banload.N,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 69 6d 61 64 77 6d 2e 65 78 65 } //02 00  \Application Data\imadwm.exe
		$a_02_1 = {5c 4c 6f 61 64 65 72 20 56 62 90 02 01 6e 65 74 5c 90 00 } //02 00 
		$a_02_2 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 90 02 08 55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 90 02 08 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 90 02 10 68 00 74 00 74 00 70 00 3a 00 90 00 } //02 00 
		$a_00_3 = {45 00 78 00 65 00 6d 00 70 00 6c 00 6f 00 3a 00 20 00 22 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 74 00 65 00 72 00 6d 00 69 00 6e 00 61 00 64 00 6f 00 2e 00 20 00 4f 00 62 00 72 00 69 00 67 00 61 00 64 00 6f 00 2e 00 22 00 } //02 00  Exemplo: "Update terminado. Obrigado."
		$a_00_4 = {45 00 78 00 65 00 6d 00 70 00 6c 00 6f 00 3a 00 20 00 22 00 4f 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 64 00 6f 00 20 00 66 00 6c 00 61 00 73 00 68 00 } //00 00  Exemplo: "O update do flash
		$a_00_5 = {5d 04 00 00 } //8d 30 
	condition:
		any of ($a_*)
 
}