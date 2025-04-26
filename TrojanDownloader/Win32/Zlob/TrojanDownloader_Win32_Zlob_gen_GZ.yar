
rule TrojanDownloader_Win32_Zlob_gen_GZ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!GZ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 49 53 41 5f 55 50 44 41 54 45 5f 5f } //2 __ISA_UPDATE__
		$a_01_1 = {5f 5f 43 4f 4d 50 4f 4e 45 4e 54 5f 53 54 41 52 54 45 44 5f 5f } //2 __COMPONENT_STARTED__
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //1 Software\Applications
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 } //1 Software\Web Technologies
		$a_00_4 = {61 77 65 72 25 64 2e 62 61 74 } //1 awer%d.bat
		$a_00_5 = {69 65 62 74 6d 2e 65 78 65 } //1 iebtm.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}