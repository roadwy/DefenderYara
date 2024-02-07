
rule TrojanDownloader_Win32_Banload_DH{
	meta:
		description = "TrojanDownloader:Win32/Banload.DH,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 6f 75 74 75 62 65 76 69 64 65 6f 73 2e 6e 6f 74 6c 6f 6e 67 2e 63 6f 6d } //01 00  youtubevideos.notlong.com
		$a_01_1 = {71 75 65 20 61 78 65 69 20 6e 6f 20 59 4f 55 2d 54 55 42 45 20 68 65 68 65 68 } //01 00  que axei no YOU-TUBE heheh
		$a_01_2 = {4f 6c 68 61 20 71 75 65 20 76 69 64 65 6f 20 6d 61 69 73 20 6c 6f 75 63 61 } //01 00  Olha que video mais louca
		$a_01_3 = {56 65 6a 61 20 63 6f 6d 6f 20 65 6c 65 20 65 20 62 6f 6d 21 21 21 } //01 00  Veja como ele e bom!!!
		$a_01_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00  UnhookWindowsHookEx
	condition:
		any of ($a_*)
 
}