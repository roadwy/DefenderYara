
rule TrojanDownloader_Win32_Monkif_W{
	meta:
		description = "TrojanDownloader:Win32/Monkif.W,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {4b 0f b6 04 19 90 03 02 02 2a c2 28 d0 90 02 06 88 04 19 90 03 01 02 49 ff c9 75 90 00 } //02 00 
		$a_03_1 = {48 74 74 33 90 02 03 c7 85 90 01 04 53 65 6e 64 90 00 } //01 00 
		$a_00_2 = {50 72 6f 33 65 73 73 33 32 } //01 00  Pro3ess32
		$a_00_3 = {43 72 70 61 74 65 54 6f 38 6c 68 65 6c 70 33 35 53 6e 61 70 30 68 6f 74 } //01 00  CrpateTo8lhelp35Snap0hot
		$a_00_4 = {25 78 78 78 25 66 64 64 25 78 67 67 25 70 6a 6a } //02 00  %xxx%fdd%xgg%pjj
		$a_02_5 = {25 63 25 73 25 63 25 73 90 02 05 70 68 6f 74 6f 2f 90 02 05 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}