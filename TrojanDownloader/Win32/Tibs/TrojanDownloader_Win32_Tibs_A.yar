
rule TrojanDownloader_Win32_Tibs_A{
	meta:
		description = "TrojanDownloader:Win32/Tibs.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 c5 81 38 4e 54 44 4c 75 90 01 01 66 81 78 04 4c 2e 75 90 00 } //10
		$a_00_1 = {c6 07 68 89 47 01 c6 47 05 c3 } //10
		$a_02_2 = {81 3f 6f 6d 6d 61 75 90 01 01 66 81 7f 04 6e 64 75 90 01 01 80 7f 06 7c 75 90 00 } //10
		$a_00_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_02_4 = {68 50 4f 53 54 58 ab b0 20 aa 8b 75 90 01 01 f3 a4 68 20 48 54 54 58 ab 68 50 2f 90 01 01 2e 58 ab b0 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_02_4  & 1)*10) >=31
 
}