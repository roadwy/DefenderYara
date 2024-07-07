
rule TrojanDownloader_O97M_Donoff_R{
	meta:
		description = "TrojanDownloader:O97M/Donoff.R,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {20 3d 20 4e 65 77 50 61 74 68 20 26 20 4e 65 77 50 61 74 68 20 26 20 22 22 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 4e 65 77 50 61 74 68 65 20 26 20 22 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 22 20 26 20 53 70 6c 69 74 28 } //1  = NewPath & NewPath & "" & "C:\Users\" & NewPathe & "\AppData\Local\Temp" & Split(
		$a_00_1 = {20 3d 20 4c 6f 76 65 73 41 6c 6c 6f 66 59 6f 75 4c 6f 76 65 59 6f 75 72 28 22 78 78 78 } //1  = LovesAllofYouLoveYour("xxx
		$a_00_2 = {67 48 4a 64 66 68 2e 65 78 65 63 28 4f 49 4b 4a 49 4b 48 4a } //1 gHJdfh.exec(OIKJIKHJ
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}