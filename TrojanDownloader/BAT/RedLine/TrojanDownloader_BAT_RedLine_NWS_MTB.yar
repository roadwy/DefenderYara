
rule TrojanDownloader_BAT_RedLine_NWS_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLine.NWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 95 02 34 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 34 00 00 00 60 1b 00 00 2b 00 00 00 f7 36 00 00 02 00 00 00 3e 00 00 00 10 00 00 00 01 } //1
		$a_81_1 = {24 64 31 63 63 32 62 61 64 2d 64 36 66 37 2d 34 37 62 38 2d 61 66 61 38 2d 33 61 39 64 34 34 33 30 64 63 63 31 } //1 $d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1
		$a_81_2 = {6c 37 57 78 30 52 38 4c 66 38 32 6a 47 74 77 38 } //1 l7Wx0R8Lf82jGtw8
		$a_81_3 = {70 53 4d 71 36 59 49 4d 33 34 39 6c 39 4a 42 39 } //1 pSMq6YIM349l9JB9
		$a_81_4 = {57 69 6e 44 6c 6c 2e 65 78 65 } //1 WinDll.exe
		$a_81_5 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //1 ConfuserEx v1.0.0
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}