
rule TrojanDownloader_Win32_Banload_AAX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAX,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 "
		
	strings :
		$a_00_0 = {ff 68 e8 03 00 00 e8 } //10
		$a_00_1 = {68 80 00 00 00 6a ec } //10
		$a_00_2 = {0b 41 32 32 32 71 ac a3 9d ff cb ca c9 ff d6 d6 } //10
		$a_00_3 = {b2 a3 ff ff ee e4 ff fb e8 dc ff 6c 55 3e ff 25 24 24 29 18 18 17 1a 00 } //10
		$a_01_4 = {54 46 72 6d 44 77 50 72 67 72 } //5 TFrmDwPrgr
		$a_01_5 = {44 2e 77 2e 50 2e 72 2e 67 2e 72 2e } //1 D.w.P.r.g.r.
		$a_01_6 = {54 46 72 6d 53 74 72 74 44 77 6e } //5 TFrmStrtDwn
		$a_01_7 = {53 2e 74 2e 72 2e 74 2e 44 2e 77 2e 6e 2e } //1 S.t.r.t.D.w.n.
		$a_01_8 = {54 66 72 50 6c 69 74 } //5 TfrPlit
		$a_01_9 = {50 6c 69 74 } //1 Plit
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5+(#a_01_7  & 1)*1+(#a_01_8  & 1)*5+(#a_01_9  & 1)*1) >=46
 
}