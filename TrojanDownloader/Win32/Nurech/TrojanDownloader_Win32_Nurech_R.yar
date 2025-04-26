
rule TrojanDownloader_Win32_Nurech_R{
	meta:
		description = "TrojanDownloader:Win32/Nurech.R,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 00 67 00 65 00 74 00 5f 00 65 00 78 00 65 00 2e 00 70 00 68 00 70 00 3f 00 6c 00 3d 00 } //10 /get_exe.php?l=
		$a_02_1 = {2e 00 65 00 78 00 65 00 90 09 0a 00 5c 00 90 04 04 04 61 2d 7a 00 90 04 04 04 30 2d 39 00 2e 00 65 00 78 00 65 00 } //10
		$a_01_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 5c 64 65 6c 73 65 6c 66 2e 62 61 74 00 00 00 00 40 65 63 68 6f 20 6f 66 66 0a 3a 74 72 79 0a 64 65 6c 20 22 00 00 00 00 22 0a 69 66 20 65 78 69 73 74 20 22 00 00 00 00 22 20 67 6f 74 6f 20 74 72 79 0a 00 64 65 6c } //5
		$a_00_3 = {c6 85 d0 fb ff ff 5c c6 85 d1 fb ff ff 64 c6 85 d2 fb ff ff 65 c6 85 d3 fb ff ff 6c c6 85 d4 fb ff ff 73 c6 85 d5 fb ff ff 65 c6 85 d6 fb ff ff 6c c6 85 d7 fb ff ff 66 c6 85 d8 fb ff ff 2e c6 85 d9 fb ff ff 62 c6 85 da fb ff ff 61 c6 85 db fb ff ff 74 } //5
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*5+(#a_00_3  & 1)*5) >=25
 
}