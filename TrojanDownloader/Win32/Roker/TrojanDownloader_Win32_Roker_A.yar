
rule TrojanDownloader_Win32_Roker_A{
	meta:
		description = "TrojanDownloader:Win32/Roker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 41 50 50 44 41 54 41 25 5c 67 6f 6f 67 6c 65 73 74 6f 72 61 67 65 2e 67 6c } //1 %APPDATA%\googlestorage.gl
		$a_01_1 = {2f 78 78 2f 67 61 74 65 2e 70 68 70 00 00 00 00 3f 75 69 64 3d 00 00 00 26 63 75 6e 3d 00 00 00 26 75 6e 3d } //1
		$a_01_2 = {4f 75 72 20 6d 6f 6d 6d 79 20 78 6f 4b 65 6c 6c 69 65 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 41 6e 6f 6e 48 54 54 50 5c 52 65 6c 65 61 73 65 5c 41 6e 6f 6e 48 54 54 50 2e 70 64 62 } //1 Our mommy xoKellie\Documents\Visual Studio 2008\Projects\AnonHTTP\Release\AnonHTTP.pdb
		$a_01_3 = {49 6e 74 65 72 6e 65 74 20 48 6f 73 74 20 50 72 6f 63 65 73 73 } //1 Internet Host Process
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}