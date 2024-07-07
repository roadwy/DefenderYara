
rule Trojan_AndroidOS_SAgnt_AG_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 69 65 75 68 61 79 2e 76 6e 2f 73 68 6f 77 2d 64 6f 77 6e 6c 6f 61 64 } //1 sieuhay.vn/show-download
		$a_01_1 = {73 65 6e 64 53 4d 53 } //1 sendSMS
		$a_01_2 = {6c 6f 61 64 44 61 74 61 46 72 6f 6d 55 72 6c 32 } //1 loadDataFromUrl2
		$a_01_3 = {63 6f 6d 2f 68 61 6d 65 64 69 61 2f 67 61 6d 65 73 74 6f 72 65 } //1 com/hamedia/gamestore
		$a_01_4 = {47 72 61 62 55 52 4c } //1 GrabURL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}