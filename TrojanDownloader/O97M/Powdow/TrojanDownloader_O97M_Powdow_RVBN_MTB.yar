
rule TrojanDownloader_O97M_Powdow_RVBN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 22 2b 22 69 22 2b 22 27 22 2b 22 77 22 2b 22 27 22 2b 22 72 22 2b 22 28 27 68 74 74 70 73 3a 2f 2f [0-64] 2f 66 69 6c 65 73 2f [0-1e] 2e 74 78 74 27 29 2d 22 2b 22 75 22 2b 22 73 22 2b 22 3f 22 2b 22 22 2b 22 22 2b 22 62 22 2b 22 29 } //1
		$a_01_1 = {61 75 74 6f 5f 6f 70 65 6e 5f 28 29 6d 73 67 62 6f 78 22 65 72 72 6f 72 21 22 63 61 6c 6c 5f 73 68 65 6c 6c 26 28 74 63 6f 6e 65 74 63 24 2c 30 29 65 6e 64 73 75 62 } //1 auto_open_()msgbox"error!"call_shell&(tconetc$,0)endsub
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_RVBN_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 3a 2f 2f 64 61 73 74 72 2e 61 78 77 65 62 73 69 74 65 2e 63 6f 6d 2f 62 69 6e 2e 65 78 65 } //1 POWERshEll.ExE wGet http://dastr.axwebsite.com/bin.exe
		$a_01_1 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 77 77 77 35 39 2e 7a 69 70 70 79 73 68 61 72 65 2e 63 6f 6d 2f 64 2f 38 6f 38 6e 5a 4e 43 78 2f 33 37 33 32 35 31 2f 6f 73 2e 65 78 65 } //1 POWERshEll.ExE wGet https://www59.zippyshare.com/d/8o8nZNCx/373251/os.exe
		$a_01_2 = {50 4f 57 45 52 73 68 45 6c 6c 2e 45 78 45 20 77 47 65 74 20 68 74 74 70 73 3a 2f 2f 77 77 77 35 36 2e 7a 69 70 70 79 73 68 61 72 65 2e 63 6f 6d 2f 64 2f 4b 6b 47 53 6f 30 4d 54 2f 31 38 35 30 39 2f 31 31 2e 65 78 65 } //1 POWERshEll.ExE wGet https://www56.zippyshare.com/d/KkGSo0MT/18509/11.exe
		$a_01_3 = {2d 6f 75 74 46 49 6c 45 20 6f 2e 65 78 65 20 20 20 3b 20 2e 5c 6f 2e 65 78 65 } //3 -outFIlE o.exe   ; .\o.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=4
 
}