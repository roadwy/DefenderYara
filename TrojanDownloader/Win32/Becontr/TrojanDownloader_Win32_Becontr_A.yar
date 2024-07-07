
rule TrojanDownloader_Win32_Becontr_A{
	meta:
		description = "TrojanDownloader:Win32/Becontr.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 74 73 2f 65 2f 67 2e 70 68 70 } //1 bts/e/g.php
		$a_01_1 = {2f 62 74 73 2f 32 33 2e 70 68 70 3f } //1 /bts/23.php?
		$a_00_2 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 } //1 \nuR\noisreVtnerruC\swodniW\tfosorciM\ERAWTFOS
		$a_03_3 = {41 50 50 44 41 54 41 90 02 20 4a 61 76 61 2e 65 78 65 90 00 } //1
		$a_03_4 = {6e 76 69 64 69 61 90 02 20 72 61 64 65 6f 6e 90 00 } //1
		$a_03_5 = {2f 62 74 73 2f 32 33 2e 70 68 70 3f 69 64 3d 90 02 20 26 76 69 64 3d 90 02 20 26 76 3d 90 02 20 26 74 79 70 65 3d 90 02 20 26 64 77 6e 6c 64 3d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}