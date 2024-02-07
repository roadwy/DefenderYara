
rule TrojanDownloader_Win32_Zlob_IB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.IB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 50 72 6f 6a 65 63 74 } //01 00  Software\NetProject
		$a_01_1 = {73 74 65 72 65 6f 2f 6d 75 73 69 63 2e 70 68 70 3f 70 61 72 61 6d 3d } //01 00  stereo/music.php?param=
		$a_01_2 = {69 6e 74 65 72 6e 65 74 73 65 63 75 72 69 74 79 } //01 00  internetsecurity
		$a_01_3 = {67 6f 6f 67 6c 65 2e } //01 00  google.
		$a_01_4 = {7b 36 42 46 35 32 41 35 32 2d 33 39 34 41 2d 31 31 44 33 2d 42 31 35 33 2d 30 30 43 30 34 46 37 39 46 41 41 36 7d } //01 00  {6BF52A52-394A-11D3-B153-00C04F79FAA6}
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //01 00  Software\Microsoft\Internet Explorer\SearchScopes
		$a_01_6 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 } //01 00  %s\zf%s%d.exe
		$a_01_7 = {2e 63 68 6c 5c 43 4c 53 49 44 } //00 00  .chl\CLSID
	condition:
		any of ($a_*)
 
}