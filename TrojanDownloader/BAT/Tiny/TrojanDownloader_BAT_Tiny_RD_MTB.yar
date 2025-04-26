
rule TrojanDownloader_BAT_Tiny_RD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 4e 6f 45 78 69 74 20 2d 43 6f 6d 6d 61 6e 64 } //powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -NoExit -Command  5
		$a_80_1 = {62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 6d 79 44 6f 77 6e 6c 6f 61 64 4a 6f 62 20 2f 64 6f 77 6e 6c 6f 61 64 20 2f 70 72 69 6f 72 69 74 79 20 6e 6f 72 6d 61 6c } //bitsadmin /transfer myDownloadJob /download /priority normal  5
		$a_80_2 = {2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 20 2f 74 6e } ///create /sc minute /mo 1 /tn  5
		$a_80_3 = {41 64 64 54 6f 53 63 68 74 61 73 6b 73 } //AddToSchtasks  4
		$a_80_4 = {73 63 68 74 61 73 6b 73 } //schtasks  4
		$a_80_5 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //ProcessStartInfo  4
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4) >=27
 
}