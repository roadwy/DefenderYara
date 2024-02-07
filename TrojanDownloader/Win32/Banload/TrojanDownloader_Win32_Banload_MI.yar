
rule TrojanDownloader_Win32_Banload_MI{
	meta:
		description = "TrojanDownloader:Win32/Banload.MI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 62 74 6e 47 3d 47 6f 6f 67 6c 65 2b 25 43 42 25 44 31 25 43 42 25 46 37 26 61 71 3d 66 26 6f 71 3d } //01 00  &btnG=Google+%CB%D1%CB%F7&aq=f&oq=
		$a_03_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 75 70 64 61 74 65 2e 65 78 65 00 00 00 ff ff ff ff 90 01 01 00 00 00 68 74 74 70 3a 2f 2f 90 02 20 2f 69 65 78 70 6c 65 72 6f 72 2f 75 70 64 61 74 65 2e 65 78 65 00 90 00 } //01 00 
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 65 72 6f 72 2e 6c 6e 6b } //02 00  \Microsoft\Internet Explorer\Quick Launch\Internet Expleror.lnk
		$a_01_3 = {6a 05 6a 00 6a 01 8b 96 20 02 00 00 8b 83 78 05 00 00 b9 05 00 00 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}