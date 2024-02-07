
rule TrojanDownloader_O97M_Donoff_CF{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CF,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {28 69 20 2d 20 31 29 20 3d 20 43 42 79 74 65 28 41 73 63 28 4d 69 64 28 } //02 00  (i - 1) = CByte(Asc(Mid(
		$a_01_1 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e 0d 0a 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e } //02 00 
		$a_01_2 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //05 00 
		$a_01_3 = {52 65 44 69 6d 20 65 73 63 75 74 63 68 65 6f 6e 28 28 28 28 55 42 6f 75 6e 64 28 61 6f 72 69 74 69 73 29 20 2b 20 31 29 20 5c 20 63 61 6c 63 65 64 29 20 2a 20 33 } //03 00  ReDim escutcheon((((UBound(aoritis) + 1) \ calced) * 3
		$a_01_4 = {74 68 72 65 65 70 65 6e 6e 79 20 42 79 56 61 6c 20 70 65 72 73 65 63 75 74 69 6f 6e 2c 20 6f 66 66 65 72 69 6e 67 28 30 29 2c 20 55 42 6f 75 6e 64 28 } //00 00  threepenny ByVal persecution, offering(0), UBound(
		$a_00_5 = {5d 04 00 00 54 } //8f 03 
	condition:
		any of ($a_*)
 
}