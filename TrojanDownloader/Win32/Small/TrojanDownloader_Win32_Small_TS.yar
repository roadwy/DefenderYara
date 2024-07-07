
rule TrojanDownloader_Win32_Small_TS{
	meta:
		description = "TrojanDownloader:Win32/Small.TS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_00_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 48 00 65 00 6c 00 70 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 66 00 69 00 6c 00 65 00 } //3 Windows Help Engine application file
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 20 20 62 6f 75 6e 64 61 72 79 3d 37 37 66 63 64 32 6e 63 6f 73 33 33 61 38 31 36 64 33 30 32 62 36 } //3 Content-Type:multipart/form-data;   boundary=77fcd2ncos33a816d302b6
		$a_01_2 = {2f 69 6e 73 74 61 6c 6c 2e 61 73 70 } //2 /install.asp
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=8
 
}