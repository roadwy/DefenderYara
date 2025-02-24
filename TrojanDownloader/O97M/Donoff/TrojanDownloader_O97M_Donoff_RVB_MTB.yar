
rule TrojanDownloader_O97M_Donoff_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 63 72 69 22 2b 22 70 74 69 6e 67 2e 64 69 63 74 22 2b 22 69 6f 6e 61 72 79 22 29 73 79 6d 62 6f 6c 64 69 63 74 2e 61 64 64 22 3f 3f 22 2c 63 68 72 77 28 26 68 34 33 30 29 73 79 6d 62 6f 6c 64 69 63 74 2e 61 64 64 22 2a 2a 22 2c 63 68 72 77 28 26 68 34 33 65 29 } //1 =createobject("scri"+"pting.dict"+"ionary")symboldict.add"??",chrw(&h430)symboldict.add"**",chrw(&h43e)
		$a_01_1 = {6d 69 64 28 66 6f 6c 64 65 72 70 61 74 68 2c 65 6e 76 76 61 72 73 74 61 72 74 2b 31 2c 65 6e 76 76 61 72 65 6e 64 2d 65 6e 76 76 61 72 73 74 61 72 74 2d 31 29 66 6f 6c 64 65 72 70 61 74 68 3d 72 65 70 6c 61 63 65 28 66 6f 6c 64 65 72 70 61 74 68 2c 22 25 22 26 65 6e 76 76 61 72 26 22 25 22 2c 65 6e 76 69 72 6f 6e 28 65 6e 76 76 61 72 29 29 } //1 mid(folderpath,envvarstart+1,envvarend-envvarstart-1)folderpath=replace(folderpath,"%"&envvar&"%",environ(envvar))
		$a_03_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 64 65 63 6f 64 65 63 6f 6e 74 65 6e 74 [0-0a] 68 65 61 64 65 72 73 65 6e 64 73 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}