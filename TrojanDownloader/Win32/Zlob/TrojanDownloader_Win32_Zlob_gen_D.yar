
rule TrojanDownloader_Win32_Zlob_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!D,SIGNATURE_TYPE_PEHSTR,09 00 09 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {33 00 00 00 75 73 65 72 00 00 00 00 68 72 6e 25 64 2e 63 6d 64 00 00 00 7a 75 00 00 22 25 73 22 } //03 00 
		$a_01_1 = {20 47 6f 00 69 73 74 20 22 25 73 22 00 00 00 00 20 45 78 00 49 66 00 00 65 6c 20 22 25 73 22 0d } //03 00 
		$a_01_2 = {64 69 00 00 72 65 5c 57 65 62 4d 00 53 6f 66 74 77 61 00 00 77 65 72 00 61 56 69 65 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}