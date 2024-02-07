
rule TrojanDownloader_Win32_Adload_CG{
	meta:
		description = "TrojanDownloader:Win32/Adload.CG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 00 45 fe 33 c0 38 45 fe 74 08 38 45 ff 74 03 } //01 00 
		$a_01_1 = {52 75 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 7e } //01 00  Run successfully~
		$a_01_2 = {31 50 62 39 34 75 63 43 41 4a 38 3d } //01 00  1Pb94ucCAJ8=
		$a_01_3 = {30 74 48 62 34 2f 7a 30 2f 66 76 38 2f 67 50 54 2f 4f 58 32 2b 77 4c 65 6e 77 3d 3d } //01 00  0tHb4/z0/fv8/gPT/OX2+wLenw==
		$a_01_4 = {39 2f 50 7a 37 36 6d 38 76 41 50 38 39 50 32 39 73 4c 57 76 38 50 34 46 41 72 30 41 2f 50 71 38 39 76 33 77 38 37 30 43 35 77 4b 66 } //00 00  9/Pz76m8vAP89P29sLWv8P4FAr0A/Pq89v3w870C5wKf
	condition:
		any of ($a_*)
 
}