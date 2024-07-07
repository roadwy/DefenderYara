
rule Trojan_AndroidOS_FakeMart_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeMart.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 53 4d 53 } //1 deleteSMS
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 46 72 6f 6d 55 72 6c 56 32 } //1 DownloadFromUrlV2
		$a_00_2 = {55 70 6c 6f 61 64 54 65 73 74 } //1 UploadTest
		$a_00_3 = {53 4d 53 53 65 6e 64 46 75 6e 63 74 69 6f 6e } //1 SMSSendFunction
		$a_00_4 = {6d 61 74 68 69 73 73 61 72 6f 78 2e 6d 79 61 72 74 73 6f 6e 6c 69 6e 65 2e 63 6f 6d 2f 6d 6f 6d 69 74 6f 6a 75 6c 69 2e 70 68 70 } //1 mathissarox.myartsonline.com/momitojuli.php
		$a_00_5 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 62 6c 61 63 6b 6d 61 72 6b 65 74 } //1 Lcom/android/blackmarket
		$a_00_6 = {4d 75 74 65 53 6f 75 6e 64 } //1 MuteSound
		$a_00_7 = {39 31 32 37 } //1 9127
		$a_00_8 = {42 44 20 4d 55 4c 54 49 4d 45 44 49 41 } //1 BD MULTIMEDIA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}