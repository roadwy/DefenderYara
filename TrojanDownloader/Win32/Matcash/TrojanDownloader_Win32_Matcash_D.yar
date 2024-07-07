
rule TrojanDownloader_Win32_Matcash_D{
	meta:
		description = "TrojanDownloader:Win32/Matcash.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 47 55 49 44 3d 00 00 26 63 6f 6e 66 69 67 76 65 72 73 69 6f 6e 3d 00 26 76 65 72 73 69 6f 6e 3d } //2
		$a_01_1 = {64 6f 75 70 64 61 74 65 3d 25 64 0a 00 } //1
		$a_01_2 = {5c 30 5c 7e 4d 68 7a 00 25 30 38 58 00 } //1
		$a_03_3 = {8d 85 64 d8 ff ff 50 ff 15 90 01 02 41 00 6a 90 01 01 ff 15 90 01 02 41 00 68 90 01 02 41 00 8d 8d 64 d8 ff ff 51 ff 15 90 00 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*4) >=6
 
}