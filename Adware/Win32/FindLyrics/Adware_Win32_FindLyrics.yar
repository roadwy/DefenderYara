
rule Adware_Win32_FindLyrics{
	meta:
		description = "Adware:Win32/FindLyrics,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 55 49 45 49 6e 6a 65 63 74 4c 69 62 57 } //1 2UIEInjectLibW
		$a_01_1 = {2e 3f 41 56 3f 24 43 43 6f 6d 41 67 67 4f 62 6a 65 63 74 40 56 43 49 6e 6a 65 63 74 4f 62 6a 65 63 74 40 40 40 41 54 4c 40 40 } //1 .?AV?$CComAggObject@VCInjectObject@@@ATL@@
		$a_01_2 = {2e 3f 41 56 43 49 45 49 6e 6a 65 63 74 4d 6f 64 75 6c 65 40 40 } //1 .?AVCIEInjectModule@@
		$a_01_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 46 00 69 00 6e 00 64 00 4c 00 79 00 72 00 69 00 63 00 73 00 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4) >=7
 
}