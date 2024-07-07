
rule TrojanDownloader_O97M_Powdow_RVBB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 64 64 6f 6e 64 2e 63 6f 6d 20 68 74 74 70 73 3a 2f 2f 74 61 78 66 69 6c 65 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 22 20 2b 20 22 66 69 6c 65 2f 76 69 78 32 67 6c 6f 67 37 35 75 32 69 6b 67 2f 33 30 2e 68 74 6d 2f 66 69 6c 65 22 } //1 C:\\ProgramData\\ddond.com https://taxfile.mediafire.com/" + "file/vix2glog75u2ikg/30.htm/file"
		$a_01_1 = {43 68 72 24 28 41 73 63 28 4d 69 64 24 28 45 6f 50 59 36 47 57 56 65 6a 2c 20 49 2c 20 31 29 29 20 2b 20 41 73 63 28 4d 69 64 24 28 47 75 53 71 77 4d 49 6f 45 38 38 46 2c 20 4a 2c 20 31 29 29 29 } //1 Chr$(Asc(Mid$(EoPY6GWVej, I, 1)) + Asc(Mid$(GuSqwMIoE88F, J, 1)))
		$a_01_2 = {52 65 70 6c 61 63 65 28 73 6f 6c 69 6e 67 65 72 69 6d 6f 2c 20 22 35 22 2c 20 22 69 22 29 } //1 Replace(solingerimo, "5", "i")
		$a_01_3 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 46 69 6e 6b 6f 6c 61 63 68 6f 6d 61 74 69 29 2e 47 65 74 28 73 6f 6c 69 6e 67 65 72 69 6d 6f 29 2e 43 72 65 61 74 65 20 6d 61 6b 77 61 6b 61 62 65 65 72 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 69 64 } //1 VBA.GetObject(Finkolachomati).Get(solingerimo).Create makwakabeer, Null, Null, pid
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}