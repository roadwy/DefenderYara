
rule TrojanDownloader_Win32_Dofoil_T_{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.T!!Dofoil.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 51 8b 34 8a 01 de 89 f0 31 c9 32 28 c1 c1 08 32 cd 40 80 38 00 75 f3 } //01 00 
		$a_01_1 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b 47 40 fe ca 75 d3 } //01 00 
		$a_01_2 = {63 6d 64 3d 67 65 74 6c 6f 61 64 26 6c 6f 67 69 6e 3d } //01 00  cmd=getload&login=
		$a_01_3 = {26 70 65 72 73 6f 6e 61 6c 3d 6f 6b 00 } //01 00 
		$a_01_4 = {26 72 65 6d 6f 76 65 64 3d 6f 6b 00 } //01 00  爦浥癯摥漽k
		$a_03_5 = {5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 00 90 01 1a 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 90 00 } //01 00 
		$a_01_6 = {25 00 73 00 5c 00 25 00 73 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 25 00 73 00 } //05 00 
	condition:
		any of ($a_*)
 
}