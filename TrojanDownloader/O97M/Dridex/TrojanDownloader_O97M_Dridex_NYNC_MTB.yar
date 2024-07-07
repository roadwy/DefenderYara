
rule TrojanDownloader_O97M_Dridex_NYNC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.NYNC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f 6f 6c 64 2d 64 61 74 61 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 74 69 6e 79 6d 63 65 2f 6c 61 6e 67 73 2f 49 30 55 4d 37 6a 42 4b 6d 5a 6d 4a 42 2e 70 68 70 90 0a 5a 00 68 74 74 70 73 3a 2f 2f 62 6f 6e 73 61 69 73 75 70 72 65 6d 65 2e 90 00 } //1
		$a_01_1 = {77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 27 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 wmic process call create 'rundll32.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}