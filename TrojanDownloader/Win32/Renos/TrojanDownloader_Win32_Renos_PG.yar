
rule TrojanDownloader_Win32_Renos_PG{
	meta:
		description = "TrojanDownloader:Win32/Renos.PG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 80 00 00 6a 00 8b 45 c8 8b 40 20 50 8b 45 c8 ff 50 54 68 00 80 00 00 6a 00 8b 45 08 50 8b 45 c8 ff 50 54 8b 55 f8 8b 65 f4 8d 84 24 00 fc ff ff 6a 00 39 c4 75 fa 81 ec 00 fc ff ff 31 c0 ff e2 } //4
		$a_01_1 = {6a 10 8b 45 c8 83 c0 0c 50 8b 45 cc 50 8b 45 c8 ff 50 58 } //2
		$a_01_2 = {3b 20 72 76 3a 35 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 35 2e 30 } //1 ; rv:5.0) Gecko/20100101 Firefox/5.0
		$a_01_3 = {2e 69 6e 2f 3f 69 6e 69 3d 00 } //1 椮⽮椿楮=
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}