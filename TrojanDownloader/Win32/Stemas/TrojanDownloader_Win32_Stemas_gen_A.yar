
rule TrojanDownloader_Win32_Stemas_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Stemas.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_00_1 = {6e 00 6f 00 76 00 6f 00 73 00 } //1 novos
		$a_00_2 = {6c 69 6e 6b 63 65 72 74 6f } //1 linkcerto
		$a_02_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 69 00 73 00 74 00 65 00 6d 00 61 00 73 00 2e 00 75 00 6e 00 69 00 6c 00 65 00 73 00 74 00 65 00 6d 00 67 00 2e 00 62 00 72 00 2f 00 63 00 6f 00 6e 00 67 00 72 00 65 00 73 00 73 00 6f 00 5f 00 73 00 61 00 75 00 64 00 65 00 2f 00 69 00 6d 00 67 00 2f 00 90 02 08 2e 00 67 00 69 00 66 00 90 00 } //1
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}