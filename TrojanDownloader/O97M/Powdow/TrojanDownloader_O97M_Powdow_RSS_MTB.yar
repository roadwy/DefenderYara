
rule TrojanDownloader_O97M_Powdow_RSS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 24 4d 6f 3d 40 28 39 31 2c 31 31 38 2c 31 31 31 2c 31 30 35 2c 31 30 30 2c 39 33 2c 39 31 2c 38 33 2c 31 32 31 2c 31 31 35 } //1 owershell.exe $Mo=@(91,118,111,105,100,93,91,83,121,115
		$a_00_1 = {52 65 70 6c 61 63 65 28 50 78 41 66 6e 44 4a 4f 50 2c 20 22 5e 22 2c 20 22 50 22 29 } //1 Replace(PxAfnDJOP, "^", "P")
		$a_00_2 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 37 32 22 20 26 20 4d 4d 4d 29 } //1 GetObject("new:72" & MMM)
		$a_00_3 = {76 35 35 2e 52 75 6e 20 73 20 26 20 6d 69 7a 2c 20 53 69 6e 28 30 2e 31 29 } //1 v55.Run s & miz, Sin(0.1)
		$a_00_4 = {4e 42 69 5a 52 7a 72 52 73 57 67 69 72 43 75 5a 6b 74 67 52 6d 63 56 4e 6d 63 66 4a 68 6e 73 20 3d 20 32 33 } //1 NBiZRzrRsWgirCuZktgRmcVNmcfJhns = 23
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}