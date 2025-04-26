
rule TrojanSpy_AndroidOS_RealRat_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 69 78 6f 2f 72 61 74 2f 6d 61 69 6e } //1 Lcom/pixo/rat/main
		$a_00_1 = {4c 63 6f 6d 2f 72 65 7a 61 2f 73 68 2f 64 65 76 69 63 65 69 6e 66 6f } //1 Lcom/reza/sh/deviceinfo
		$a_00_2 = {35 2e 32 35 35 2e 31 31 37 2e 31 31 35 } //1 5.255.117.115
		$a_00_3 = {50 4e 55 70 6c 6f 61 64 46 69 6c 65 } //1 PNUploadFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanSpy_AndroidOS_RealRat_H_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,2a 00 2a 00 09 00 00 "
		
	strings :
		$a_01_0 = {69 72 2e 4d 72 41 76 65 6e 74 65 72 2e 69 70 74 76 } //10 ir.MrAventer.iptv
		$a_01_1 = {74 61 72 67 65 74 61 64 64 72 65 73 73 } //10 targetaddress
		$a_01_2 = {68 69 64 65 41 70 70 49 63 6f 6e } //10 hideAppIcon
		$a_01_3 = {7e 74 65 73 74 2e 74 65 73 74 } //10 ~test.test
		$a_01_4 = {50 4e 53 4d 53 } //10 PNSMS
		$a_01_5 = {69 73 52 75 6e 6e 69 6e 67 4f 6e 45 6d 75 6c 61 74 6f 72 } //10 isRunningOnEmulator
		$a_01_6 = {61 6c 6c 5f 73 6d 73 } //1 all_sms
		$a_01_7 = {61 70 70 5f 6c 69 73 74 } //1 app_list
		$a_01_8 = {68 69 64 65 5f 61 6c 6c } //1 hide_all
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=42
 
}