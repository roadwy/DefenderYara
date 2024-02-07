
rule TrojanDownloader_Win32_Zlob_gen_W{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_1 = {4f 70 65 6e 45 76 65 6e 74 57 } //01 00  OpenEventW
		$a_00_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00 00 00 } //01 00 
		$a_02_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 90 02 40 2f 00 64 00 77 00 2e 00 70 00 68 00 70 00 90 00 } //02 00 
		$a_01_4 = {62 00 78 00 31 00 38 00 64 00 78 00 76 00 2e 00 64 00 61 00 74 00 } //01 00  bx18dxv.dat
		$a_01_5 = {4d 00 79 00 42 00 49 00 54 00 53 00 54 00 72 00 61 00 6e 00 73 00 5f 00 6e 00 65 00 77 00 } //00 00  MyBITSTrans_new
	condition:
		any of ($a_*)
 
}