
rule TrojanDownloader_O97M_Donoff_gen_C{
	meta:
		description = "TrojanDownloader:O97M/Donoff.gen!C,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If Win64 Then
		$a_00_1 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_00_2 = {45 6e 76 69 72 6f 6e 28 22 74 } //1 Environ("t
		$a_00_3 = {62 20 3d 20 22 78 65 22 } //1 b = "xe"
		$a_00_4 = {2e 65 22 20 26 20 62 } //1 .e" & b
		$a_00_5 = {4e 65 77 20 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 33 30 } //1 New MSXML2.XMLHTTP30
		$a_00_6 = {4f 70 65 6e 20 61 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 } //1 Open a For Binary As #
		$a_00_7 = {2e 32 34 32 2e 31 32 33 2e 32 31 31 3a 38 38 } //1 .242.123.211:88
		$a_00_8 = {38 30 2e 32 34 32 2e 31 32 33 2e 32 22 20 26 20 22 31 31 3a 38 38 38 2f } //1 80.242.123.2" & "11:888/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}