
rule TrojanDownloader_Win32_Ciucio_C{
	meta:
		description = "TrojanDownloader:Win32/Ciucio.C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {3a 5c 44 72 6f 70 62 6f 78 5c 4d 79 20 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 74 6f 73 5c 6a 61 76 61 6e 5c 73 74 61 72 74 5c } //01 00  :\Dropbox\My Dropbox\Projetos\javan\start\
		$a_00_1 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_03_2 = {5c 54 45 4d 50 00 90 01 09 00 5c 54 4d 50 00 90 00 } //01 00 
		$a_00_3 = {57 73 68 69 70 36 2e 64 6c 6c } //01 00  Wship6.dll
		$a_01_4 = {53 00 56 00 43 00 48 00 4f 00 53 00 54 00 } //00 00  SVCHOST
	condition:
		any of ($a_*)
 
}