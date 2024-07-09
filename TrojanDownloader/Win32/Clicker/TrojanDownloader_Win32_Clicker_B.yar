
rule TrojanDownloader_Win32_Clicker_B{
	meta:
		description = "TrojanDownloader:Win32/Clicker.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 45 47 49 4e 00 00 00 31 00 00 00 54 59 50 45 00 00 00 00 63 6c 69 63 6b 3d 25 73 0a 00 00 00 43 4c 49 43 4b 00 00 00 52 6f 6f 74 00 00 00 00 } //1
		$a_00_1 = {52 5b 66 66 7d 54 04 03 5c 5b 45 34 61 7d 7d 79 33 26 26 } //1
		$a_03_2 = {04 03 4a 45 40 4a 42 34 (04 03 5d 50 59 4c 34|61 7d 7d 79 33 26 26) } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}