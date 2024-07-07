
rule TrojanDownloader_Win32_Genome_U{
	meta:
		description = "TrojanDownloader:Win32/Genome.U,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_02_0 = {47 83 c0 02 0f b7 28 66 83 fd 20 77 90 01 01 8b c3 8b d7 e8 90 01 04 8b c6 8b 33 33 c9 eb 90 00 } //2
		$a_00_1 = {63 00 76 00 73 00 73 00 72 00 76 00 2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 75 00 6e 00 73 00 65 00 72 00 69 00 76 00 63 00 65 00 } //2 cvssrv.exe -runserivce
		$a_00_2 = {2f 00 64 00 31 00 2e 00 7a 00 69 00 70 00 } //1 /d1.zip
		$a_00_3 = {77 00 64 00 62 00 2e 00 64 00 6c 00 6c 00 } //1 wdb.dll
		$a_00_4 = {77 00 64 00 63 00 2e 00 64 00 6c 00 6c 00 } //1 wdc.dll
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}