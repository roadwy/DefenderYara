
rule TrojanDownloader_BAT_AgentTesla_NPY_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_80_0 = {73 65 6c 69 66 2f 6d 6f 63 2e 30 31 2d 6e 69 6f 63 2d 6e 69 6f 63 2d 65 6c 69 66 2f 2f 3a 70 74 74 68 } //selif/moc.01-nioc-nioc-elif//:ptth  10
		$a_80_1 = {2f 74 65 67 2f 68 73 2e 72 65 66 73 6e 61 72 74 2f 2f 3a 73 70 74 74 68 } ///teg/hs.refsnart//:sptth  10
		$a_80_2 = {47 46 46 51 46 46 44 53 46 57 51 46 57 51 46 57 51 } //GFFQFFDSFWQFWQFWQ  1
		$a_80_3 = {44 57 51 44 57 51 44 51 57 44 51 57 44 57 51 44 51 57 } //DWQDWQDQWDQWDWQDQW  1
		$a_80_4 = {4e 6f 6e 6f 2e 4e 6f 6e 6f } //Nono.Nono  1
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_7 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}