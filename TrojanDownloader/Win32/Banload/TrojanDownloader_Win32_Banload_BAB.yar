
rule TrojanDownloader_Win32_Banload_BAB{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 53 79 73 74 65 6d 20 49 6e 66 6f 2e 2e 2e } //01 00  &System Info...
		$a_01_1 = {57 61 72 6e 69 6e 67 3a 20 2e 2e 2e } //01 00  Warning: ...
		$a_01_2 = {43 65 6e 74 72 61 6c 20 64 65 20 53 65 67 75 72 61 6e } //02 00  Central de Seguran
		$a_01_3 = {5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 } //02 00  \Application Data\imadwm.exe
		$a_01_4 = {5c 00 42 00 61 00 6e 00 6b 00 73 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 73 00 } //00 00  \Banks\Loaders
		$a_01_5 = {00 5d 04 00 } //00 79 
	condition:
		any of ($a_*)
 
}