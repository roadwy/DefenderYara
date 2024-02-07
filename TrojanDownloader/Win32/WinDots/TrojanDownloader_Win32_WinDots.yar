
rule TrojanDownloader_Win32_WinDots{
	meta:
		description = "TrojanDownloader:Win32/WinDots,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 53 6f 66 74 77 61 72 65 5c 64 6f 75 62 6c 65 70 6f 69 6e 74 } //01 00  \Software\doublepoint
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 68 6f 70 2e 64 6f 75 62 6c 65 70 6f 69 6e 74 2e 6e 65 74 2f 2f 69 6e 73 74 61 6c 6c 2f 75 70 6c 69 73 74 32 2e 70 68 70 3f 70 69 64 3d } //01 00  http://shop.doublepoint.net//install/uplist2.php?pid=
		$a_01_2 = {68 74 74 70 3a 2f 2f 73 68 6f 70 2e 64 6f 75 62 6c 65 70 6f 69 6e 74 2e 6e 65 74 2f 69 6e 73 74 61 6c 6c 2f 70 5f 62 6f 6f 74 2e 70 68 70 } //01 00  http://shop.doublepoint.net/install/p_boot.php
		$a_01_3 = {5c 53 6f 66 74 77 61 72 65 5c 77 69 6e 64 6f 74 73 } //01 00  \Software\windots
		$a_01_4 = {64 70 75 70 2e 64 6c 6c } //01 00  dpup.dll
		$a_01_5 = {7b 39 30 30 46 34 34 31 32 2d 43 35 46 34 2d 34 42 35 43 2d 42 46 35 44 2d 46 37 33 44 35 44 34 35 38 42 39 42 7d } //00 00  {900F4412-C5F4-4B5C-BF5D-F73D5D458B9B}
	condition:
		any of ($a_*)
 
}