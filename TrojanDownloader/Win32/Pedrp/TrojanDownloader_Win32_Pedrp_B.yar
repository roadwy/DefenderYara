
rule TrojanDownloader_Win32_Pedrp_B{
	meta:
		description = "TrojanDownloader:Win32/Pedrp.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 68 13 00 00 20 56 89 6c 24 2c c7 44 24 34 04 00 00 00 ff d7 85 c0 74 } //1
		$a_02_1 = {3d 94 01 00 00 74 90 01 01 3d 93 01 00 00 74 90 01 01 8d 54 24 90 01 01 8d 44 24 90 01 01 52 8d 4c 24 90 01 01 50 51 68 05 00 00 20 56 89 6c 24 24 c7 44 24 38 04 00 00 00 89 6c 24 3c ff d7 90 00 } //1
		$a_00_2 = {64 6f 77 6e 20 66 69 6c 65 20 73 75 63 63 65 73 73 } //1 down file success
		$a_00_3 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 20 65 72 72 6f 72 3a 25 64 } //1 Internet connect error:%d
		$a_01_4 = {41 76 61 6c 69 61 62 6c 65 20 64 61 74 61 3a 25 75 20 62 79 74 65 73 } //1 Avaliable data:%u bytes
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}