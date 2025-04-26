
rule Trojan_O97M_Kerdown_C{
	meta:
		description = "Trojan:O97M/Kerdown.C,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 61 69 6e 5f 62 61 63 6b 67 72 6f 75 6e 64 2e 70 6e 67 } //1 \main_background.png
		$a_01_1 = {5c 53 65 63 75 72 69 74 79 41 6e 64 4d 61 69 6e 74 65 6e 61 6e 63 65 5f 45 72 72 6f 72 2e 70 6e 67 } //1 \SecurityAndMaintenance_Error.png
		$a_01_2 = {5c 57 69 6e 77 6f 72 64 55 70 64 61 74 65 73 2e 65 78 65 } //1 \WinwordUpdates.exe
		$a_01_3 = {26 20 22 5c 77 77 6c 69 62 2e 64 6c 6c 22 } //1 & "\wwlib.dll"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}