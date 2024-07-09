
rule Virus_Win32_Xorer_K{
	meta:
		description = "Virus:Win32/Xorer.K,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {c2 10 00 68 ?? ?? ?? 00 6a 01 6a 00 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 3d b7 00 00 00 75 12 5f 5e 5d b8 01 00 00 00 5b 81 c4 ?? ?? 00 00 c2 10 00 } //2
		$a_00_1 = {64 67 68 61 75 77 65 75 67 73 64 67 65 72 68 } //2 dghauweugsdgerh
		$a_00_2 = {4d 53 49 43 54 46 49 4d 45 20 53 4d 53 53 } //1 MSICTFIME SMSS
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {4d 43 49 20 50 72 6f 67 72 61 6d 20 43 6f 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e } //1 MCI Program Com Application
		$a_01_5 = {00 58 4f 52 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}