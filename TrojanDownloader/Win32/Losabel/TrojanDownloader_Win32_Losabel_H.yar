
rule TrojanDownloader_Win32_Losabel_H{
	meta:
		description = "TrojanDownloader:Win32/Losabel.H,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 40 77 1b 00 6a 00 6a 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 e8 03 00 00 e8 90 00 } //1
		$a_03_1 = {6a 00 ff 16 85 c0 68 c8 00 00 00 e8 90 01 02 ff ff 6a 00 6a 00 6a 00 68 90 01 02 40 00 68 90 01 02 40 00 6a 00 ff 13 6a 00 90 00 } //1
		$a_00_2 = {76 69 73 74 61 41 2e 65 78 65 } //1 vistaA.exe
		$a_00_3 = {4c 6f 76 65 48 65 62 65 } //1 LoveHebe
		$a_00_4 = {72 61 76 6d 6f 6e 64 2e 65 78 65 } //1 ravmond.exe
		$a_00_5 = {33 36 30 53 61 66 65 2e 65 78 65 } //1 360Safe.exe
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}