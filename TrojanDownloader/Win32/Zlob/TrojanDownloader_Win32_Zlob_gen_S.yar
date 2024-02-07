
rule TrojanDownloader_Win32_Zlob_gen_S{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2f 73 65 61 72 63 68 2e 70 68 70 3f 71 71 3d 25 73 } //0a 00  /search.php?qq=%s
		$a_01_1 = {43 4c 41 46 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 } //05 00 
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 75 00 74 00 6f 00 2e 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 6d 00 73 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 2e 00 61 00 73 00 70 00 3f 00 4d 00 54 00 3d 00 } //05 00  http://auto.search.msn.com/response.asp?MT=
		$a_01_3 = {2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 70 00 68 00 70 00 3f 00 71 00 71 00 3d 00 25 00 73 00 } //01 00  /search.php?qq=%s
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //00 00  Software\Microsoft\Internet Explorer\Main
	condition:
		any of ($a_*)
 
}