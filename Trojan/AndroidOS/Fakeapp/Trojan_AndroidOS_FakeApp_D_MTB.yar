
rule Trojan_AndroidOS_FakeApp_D_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 64 6f 62 65 66 6c 61 73 68 70 6c 61 79 65 72 2e 6d 6f 62 69 } //10 adobeflashplayer.mobi
		$a_01_1 = {32 34 2d 62 75 73 69 6e 65 73 73 2e 63 6f 6d 2f } //10 24-business.com/
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 2e 6d 61 63 72 6f 6d 65 64 69 61 2e } //5 download.macromedia.
		$a_01_3 = {77 69 6d 61 78 49 6e 66 6f } //5 wimaxInfo
		$a_01_4 = {65 6d 61 69 6c 49 6e 74 65 6e 74 32 } //1 emailIntent2
		$a_01_5 = {68 61 73 6d 6f 62 6f 67 65 6e 69 65 } //1 hasmobogenie
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}