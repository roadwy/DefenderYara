
rule TrojanDownloader_O97M_Powdow_RVT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 53 6f 75 72 63 65 20 68 74 74 60 70 73 3a 2f 2f 73 65 63 75 72 30 2e 78 32 34 68 72 2e 63 6f 6d 2f 61 2f 43 6f 6e 73 6f 6c 65 41 70 70 31 34 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 72 65 74 75 72 6e 6f 74 68 65 72 2e 65 60 78 65 } //1 -Source htt`ps://secur0.x24hr.com/a/ConsoleApp14.e`xe -Dest C:\Users\Public\Documents\returnother.e`xe
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 43 68 72 28 31 31 30 29 20 26 20 22 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 22 20 26 20 43 49 6e 74 28 30 2e 33 29 29 2e 4f 70 65 6e 20 28 64 72 69 76 65 72 69 73 6b 29 } //1 GetObject(Chr(110) & "ew:13709620-C279-11CE-A49E-44455354000" & CInt(0.3)).Open (driverisk)
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 67 6f 64 2e 62 61 74 } //1 C:\Users\Public\Documents\god.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}