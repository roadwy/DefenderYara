
rule Trojan_Win32_Msposer_G{
	meta:
		description = "Trojan:Win32/Msposer.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 73 31 34 2e 63 6e 7a 7a 2e 63 6f 6d 2f 73 74 61 74 2e 70 68 70 3f 69 64 3d 34 37 33 30 34 32 37 26 77 65 62 5f 69 64 3d 34 37 33 30 34 32 37 } //01 00  //s14.cnzz.com/stat.php?id=4730427&web_id=4730427
		$a_01_1 = {2f 73 74 61 74 2f 67 61 6d 65 2e 70 68 70 3f 74 79 70 65 3d 00 00 00 00 77 77 77 2e 68 75 69 66 65 69 64 65 7a 68 75 2e 63 6f 6d } //01 00 
		$a_01_2 = {5c 65 78 74 5c 73 65 74 74 69 6e 67 73 5c 7b 31 31 66 30 39 61 66 65 2d 37 35 61 64 2d 34 65 35 32 2d 61 62 34 33 2d 65 30 39 65 39 33 35 31 63 65 31 37 7d } //00 00  \ext\settings\{11f09afe-75ad-4e52-ab43-e09e9351ce17}
	condition:
		any of ($a_*)
 
}