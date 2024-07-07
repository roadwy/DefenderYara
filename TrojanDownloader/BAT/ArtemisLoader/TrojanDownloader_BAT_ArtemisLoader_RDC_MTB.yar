
rule TrojanDownloader_BAT_ArtemisLoader_RDC_MTB{
	meta:
		description = "TrojanDownloader:BAT/ArtemisLoader.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 65 65 35 32 30 63 62 2d 39 64 38 36 2d 34 37 34 32 2d 62 61 30 62 2d 37 38 65 63 31 65 31 33 32 61 63 34 } //1 aee520cb-9d86-4742-ba0b-78ec1e132ac4
		$a_01_1 = {2f 00 2f 00 70 00 75 00 72 00 65 00 73 00 76 00 72 00 30 00 31 00 2e 00 73 00 79 00 74 00 65 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 64 00 61 00 73 00 68 00 62 00 6f 00 61 00 72 00 64 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 41 00 66 00 78 00 75 00 66 00 6f 00 74 00 74 00 76 00 2e 00 62 00 6d 00 70 00 } //1 //puresvr01.sytes.net/dashboard/panel/uploads/Afxufottv.bmp
		$a_01_2 = {50 00 63 00 78 00 7a 00 62 00 74 00 2e 00 4b 00 6a 00 73 00 61 00 70 00 6b 00 6e 00 6c 00 65 00 68 00 68 00 61 00 63 00 72 00 75 00 6e 00 65 00 75 00 70 00 63 00 75 00 } //1 Pcxzbt.Kjsapknlehhacruneupcu
		$a_01_3 = {59 00 65 00 77 00 6b 00 79 00 63 00 73 00 6f 00 72 00 6e 00 78 00 69 00 71 00 } //1 Yewkycsornxiq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}