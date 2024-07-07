
rule TrojanDownloader_O97M_Amphitryon_MK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Amphitryon.MK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 72 6f 67 72 61 6d 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 24 70 61 74 68 20 3d 20 24 45 6e 76 3a 74 65 6d 70 2b 27 5c 90 02 10 2e 65 78 65 27 90 00 } //1
		$a_01_1 = {24 63 6c 69 65 6e 74 2e 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 74 68 65 2e 65 61 72 74 68 2e 6c 69 2f 7e 73 67 74 61 74 68 61 6d 2f 70 75 74 74 79 2f 6c 61 74 65 73 74 2f 77 33 32 2f 70 75 74 74 79 2e 65 78 65 27 2c 24 70 61 74 68 29 } //1 $client.downloadfile('https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe',$path)
		$a_01_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 20 24 70 61 74 68 } //1 Start-Process -FilePath $path
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}