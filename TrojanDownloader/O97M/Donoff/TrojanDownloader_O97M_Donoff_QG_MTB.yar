
rule TrojanDownloader_O97M_Donoff_QG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 20 6f 63 6e 65 2d 20 6e 65 64 64 69 68 20 65 6c 79 74 73 77 6f 64 6e 69 77 2d 20 6c 6c 65 68 73 72 65 77 6f 70 } //1 S ocne- neddih elytswodniw- llehsrewop
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 2e } //1 GetObject("winmgmts:root\cimv2:Win32_Process").
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}