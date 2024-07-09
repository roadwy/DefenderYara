
rule TrojanDownloader_Win32_Banload{
	meta:
		description = "TrojanDownloader:Win32/Banload,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d7 88 c1 c1 e8 08 8b 5d ?? d7 30 c1 c1 e8 08 8b 5d ?? d7 30 c1 c1 e8 08 8b 5d ?? d7 } //1
		$a_03_1 = {55 89 e5 50 8b 45 ?? c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 c6 00 ?? 40 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Banload_2{
	meta:
		description = "TrojanDownloader:Win32/Banload,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 40 ff 28 30 ff 01 00 fc f6 68 ff f4 1e 70 50 ff f3 ff 00 70 52 ff 28 10 ff 01 00 04 58 ff 80 0c 00 4a fd 69 20 ff fe 68 f0 fe 77 01 0a ?? 00 00 00 04 68 ff 28 30 ff 01 00 fb } //1
		$a_01_1 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 00 } //1
		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 00 00 } //1
		$a_01_3 = {53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Banload_3{
	meta:
		description = "TrojanDownloader:Win32/Banload,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 73 6c 38 35 39 2e 77 65 62 73 69 74 65 73 65 67 75 72 6f 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 66 6c 61 73 68 2f 64 61 64 6f 73 2f 67 72 64 6d 6f 64 79 2e 6a 70 67 } //1 https://ssl859.websiteseguro.com/downloadflash/dados/grdmody.jpg
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 73 73 6c 38 35 39 2e 77 65 62 73 69 74 65 73 65 67 75 72 6f 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 66 6c 61 73 68 2f 64 61 64 6f 73 2f 6d 73 6e 47 52 44 2e 6a 70 67 } //1 https://ssl859.websiteseguro.com/downloadflash/dados/msnGRD.jpg
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 73 73 6c 38 35 39 2e 77 65 62 73 69 74 65 73 65 67 75 72 6f 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 66 6c 61 73 68 2f 64 61 64 6f 73 2f 4a 75 6c 69 61 6e 61 2e 6a 70 67 } //1 https://ssl859.websiteseguro.com/downloadflash/dados/Juliana.jpg
		$a_01_3 = {6d 73 6e 6d 73 67 61 73 71 77 65 72 74 73 2e 74 78 74 } //1 msnmsgasqwerts.txt
		$a_01_4 = {6a 75 6c 69 61 6e 61 73 2e 74 78 74 } //1 julianas.txt
		$a_01_5 = {61 72 6d 6f 72 2e 74 78 74 } //1 armor.txt
		$a_01_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 72 00 2e 00 79 00 6f 00 75 00 74 00 75 00 62 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 61 00 74 00 63 00 68 00 3f 00 76 00 3d 00 72 00 64 00 6f 00 37 00 7a 00 62 00 38 00 78 00 69 00 76 00 30 00 26 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 3d 00 72 00 65 00 6c 00 61 00 74 00 65 00 64 00 } //1 http://br.youtube.com/watch?v=rdo7zb8xiv0&feature=related
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}