
rule Trojan_AndroidOS_SAgnt_BC_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 69 76 65 72 42 52 31 } //1 deliverBR1
		$a_01_1 = {73 65 6e 74 42 52 31 } //1 sentBR1
		$a_01_2 = {2f 73 64 63 61 72 64 2f 64 6f 77 6e 6c 6f 61 64 65 64 66 69 6c 65 2e 61 70 6b } //1 /sdcard/downloadedfile.apk
		$a_01_3 = {76 6e 2f 61 64 66 6c 65 78 2f 61 64 73 } //1 vn/adflex/ads
		$a_01_4 = {41 64 73 53 65 72 76 69 63 65 } //1 AdsService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}