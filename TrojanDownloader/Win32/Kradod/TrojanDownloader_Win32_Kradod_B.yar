
rule TrojanDownloader_Win32_Kradod_B{
	meta:
		description = "TrojanDownloader:Win32/Kradod.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f3 ab b9 08 00 00 00 8d 7c 90 01 02 f3 ab 8d 44 90 01 02 50 68 90 01 04 68 90 01 04 6a 03 e8 90 00 } //1
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 64 6f 61 64 00 } //1 潓瑦慷敲摜慯d
		$a_00_2 = {25 73 55 49 44 3d 25 73 26 4f 53 56 3d 25 73 26 49 45 56 3d 25 73 26 56 45 52 3d 25 73 } //1 %sUID=%s&OSV=%s&IEV=%s&VER=%s
		$a_00_3 = {55 70 45 78 65 55 72 6c } //1 UpExeUrl
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}