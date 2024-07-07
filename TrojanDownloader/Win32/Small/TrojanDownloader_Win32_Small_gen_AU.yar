
rule TrojanDownloader_Win32_Small_gen_AU{
	meta:
		description = "TrojanDownloader:Win32/Small.gen!AU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 61 } //1 urldownloadtofilea
		$a_01_1 = {25 6c 75 2e 65 78 65 } //1 %lu.exe
		$a_00_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
		$a_00_3 = {77 69 6e 6c 6f 67 61 6e 2e 65 78 65 } //1 winlogan.exe
		$a_02_4 = {68 74 74 70 3a 2f 2f 90 02 20 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}