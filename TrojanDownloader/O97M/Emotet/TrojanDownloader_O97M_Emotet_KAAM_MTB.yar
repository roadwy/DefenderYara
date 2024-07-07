
rule TrojanDownloader_O97M_Emotet_KAAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.KAAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 76 69 63 6b 69 70 6f 68 6c 2e 63 6f 6d 2f 61 45 33 49 37 71 4b 51 56 67 44 7a 71 44 31 2f } //1 ://vickipohl.com/aE3I7qKQVgDzqD1/
		$a_01_1 = {3a 2f 2f 77 77 77 2e 76 69 73 69 6f 6e 73 66 61 6e 74 61 73 74 69 63 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 51 58 42 4a 37 4e 37 6a 61 58 66 36 70 5a 69 32 4a 36 2f } //1 ://www.visionsfantastic.com/images/QXBJ7N7jaXf6pZi2J6/
		$a_01_2 = {3a 2f 2f 77 65 61 72 65 6f 6e 65 2d 62 68 2e 6f 72 67 2f 69 6b 38 45 46 75 58 71 63 2f } //1 ://weareone-bh.org/ik8EFuXqc/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}