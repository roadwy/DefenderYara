
rule TrojanDownloader_O97M_Obfuse_PDH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 66 6e 6e 6b } //1 =chr(50)+chr(48)+chr(48)fnnk
		$a_01_1 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 } //1 specialpath=wshshell.specialfolders("recent")
		$a_01_2 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 6f 6d 6a 69 68 6a 6e 62 68 67 68 67 68 67 76 6a 76 28 22 69 5e 5f 6f 78 64 75 78 76 5b 3b 6e 6e 22 29 63 73 74 65 73 75 2e 6f 70 65 6e 22 67 65 74 22 2c 6f 6d 6a 69 68 6a 6e 62 68 67 68 67 68 67 76 6a 76 } //1 =specialpath+omjihjnbhghghgvjv("i^_oxduxv[;nn")cstesu.open"get",omjihjnbhghghgvjv
		$a_01_3 = {2e 77 72 69 74 65 74 66 64 76 65 67 68 6f 69 6d 6a 69 6e 2e 73 61 76 65 74 6f 66 69 6c 65 78 79 75 68 76 6c 61 2c 76 74 66 71 63 79 77 2b 76 74 66 71 63 79 77 2b 66 64 73 6e 6b 6a 6e 73 64 2b 6f 6a 68 69 68 62 68 6a 62 62 6f 69 6d 6a 69 6e 2e } //1 .writetfdveghoimjin.savetofilexyuhvla,vtfqcyw+vtfqcyw+fdsnkjnsd+ojhihbhjbboimjin.
		$a_01_4 = {2e 6f 70 65 6e 28 78 79 75 68 76 6c 61 29 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e } //1 .open(xyuhvla)endsubfunction
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}