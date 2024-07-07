
rule TrojanDownloader_Win32_Calacreo_A{
	meta:
		description = "TrojanDownloader:Win32/Calacreo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 70 3d 64 69 72 75 70 6c 6f 61 64 31 32 33 26 69 64 3d } //1 &p=dirupload123&id=
		$a_01_1 = {26 70 3d 62 6f 74 31 32 33 26 69 64 3d } //1 &p=bot123&id=
		$a_01_2 = {26 70 3d 63 65 72 74 31 32 33 26 69 64 3d } //1 &p=cert123&id=
		$a_03_3 = {6d 6f 64 75 6c 65 73 2f 64 6f 63 73 2f 90 02 20 69 6e 64 65 78 31 2e 70 68 70 3f 76 65 72 3d 90 00 } //1
		$a_03_4 = {6a 00 6a 1a 68 90 01 04 6a 00 ff d0 be 90 01 04 fc 83 e1 00 8a 06 50 9c 58 25 00 04 00 00 83 f8 00 75 05 83 c6 01 eb 03 83 ee 01 58 3c 00 74 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}