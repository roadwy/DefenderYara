
rule TrojanDownloader_Win32_Olutall_A{
	meta:
		description = "TrojanDownloader:Win32/Olutall.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 00 2f 00 75 00 6c 00 2e 00 74 00 6f 00 2f 00 } //01 00  //ul.to/
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5f 00 53 00 65 00 72 00 76 00 65 00 72 00 } //01 00  Internet Explorer_Server
		$a_01_2 = {57 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 74 00 6f 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 } //01 00  Welcome to Installer
		$a_01_3 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //01 00  Install Your Software
		$a_01_4 = {53 00 65 00 74 00 75 00 70 00 31 00 2e 00 65 00 78 00 65 00 } //01 00  Setup1.exe
		$a_01_5 = {2f 00 73 00 20 00 2f 00 76 00 2f 00 71 00 6e 00 20 00 41 00 47 00 52 00 45 00 45 00 54 00 4f 00 4c 00 49 00 43 00 45 00 4e 00 53 00 45 00 3d 00 79 00 65 00 73 00 } //00 00  /s /v/qn AGREETOLICENSE=yes
		$a_00_6 = {5d 04 00 00 1e } //63 03 
	condition:
		any of ($a_*)
 
}