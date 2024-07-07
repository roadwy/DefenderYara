
rule TrojanDownloader_Win32_Zlob_gen_AM{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 14 07 00 00 74 15 3d 15 07 00 00 74 0e 3d 17 07 00 00 74 07 3d 16 07 00 00 75 60 33 c0 89 45 d8 c7 05 } //1
		$a_01_1 = {53 54 41 52 54 45 52 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}