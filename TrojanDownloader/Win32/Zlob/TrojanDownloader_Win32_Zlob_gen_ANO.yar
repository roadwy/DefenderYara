
rule TrojanDownloader_Win32_Zlob_gen_ANO{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!ANO,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 6f 76 6e 6f 2d 61 76 61 73 74 21 } //02 00  govno-avast!
		$a_01_1 = {57 65 62 4d 65 64 69 61 56 69 65 77 65 72 } //01 00  WebMediaViewer
		$a_01_2 = {70 69 64 6f 72 61 73 79 76 73 68 74 61 62 65 00 34 30 32 00 } //02 00  楰潤慲祳獶瑨扡e〴2
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //02 00  CreateToolhelp32Snapshot
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}