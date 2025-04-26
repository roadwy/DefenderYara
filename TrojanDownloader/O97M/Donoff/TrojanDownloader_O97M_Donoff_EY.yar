
rule TrojanDownloader_O97M_Donoff_EY{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 72 73 22 } //1 = "powers"
		$a_00_1 = {3d 20 70 6f 36 48 20 2b 20 22 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 } //1 = po6H + "hell.exe -nop -w hidden -e
		$a_00_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 70 6f 36 48 2c 20 76 62 48 69 64 65 29 } //1 Call Shell(po6H, vbHide)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_EY_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {47 76 63 4d 69 6a 73 20 3d 20 53 62 74 68 77 56 49 44 69 6e 46 20 2b 20 49 54 63 6b 6e 4e 4e 76 58 59 0d 0a 56 42 41 2e 53 68 65 6c 6c 24 20 47 76 63 4d 69 6a 73 2c 20 30 0d 0a 45 6e 64 20 53 75 62 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 77 4c 62 46 43 43 50 49 69 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_EY_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 22 20 2b 20 22 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 45 78 22 20 2b 20 22 65 63 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 22 20 2b 20 22 61 6e 64 20 28 4e 65 77 2d 4f 62 6a 65 22 20 2b 20 22 63 74 20 53 79 73 74 22 20 2b 20 22 65 6d 2e 4e 65 74 2e 57 65 62 43 22 20 2b 20 22 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 22 20 2b 20 22 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f } //1 = "powe" + "rshell -nop -Ex" + "ec Bypass -Comm" + "and (New-Obje" + "ct Syst" + "em.Net.WebC" + "lient).Downl" + "oadFile('http://
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_EY_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set oShell = CreateObject("WScript.Shell")
		$a_01_1 = {6f 53 68 65 6c 6c 2e 52 75 6e 20 } //1 oShell.Run 
		$a_01_2 = {3d 20 22 70 6f 77 65 22 20 2b 20 22 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 22 20 2b 20 22 77 53 74 79 6c 65 20 48 69 64 22 20 2b 20 22 64 65 6e } //1 = "powe" + "rshell -Windo" + "wStyle Hid" + "den
		$a_03_3 = {2e 6e 65 78 74 28 31 2c 20 36 35 35 33 36 29 3b [0-10] 20 3d 20 24 65 6e 76 3a 74 65 6d 70 20 2b 20 27 27 20 2b 20 [0-10] 20 2b 20 27 2e 65 78 65 27 3b 66 6f 72 65 61 63 68 28 } //1
		$a_03_4 = {3d 20 22 63 6d 64 20 2f 63 20 62 69 74 73 61 22 20 2b 20 22 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 [0-10] 20 2f 70 72 69 6f 72 22 20 2b 20 22 69 74 79 20 68 69 67 68 20 68 74 74 70 3a 2f 2f } //1
		$a_03_5 = {25 74 65 6d 22 20 2b 20 22 70 25 5c [0-10] 2e 65 78 65 20 26 20 73 74 61 72 74 20 2f 57 41 49 54 20 25 74 65 22 20 2b 20 22 6d 70 25 5c [0-10] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}