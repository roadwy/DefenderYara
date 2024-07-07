
rule Trojan_AndroidOS_Ahmyth_T{
	meta:
		description = "Trojan:AndroidOS/Ahmyth.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 69 65 6e 64 20 52 65 71 75 65 73 74 20 43 61 6e 63 65 6c 6c 65 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Friend Request Cancelled Successfully
		$a_01_1 = {75 70 6c 6f 61 64 4f 76 65 72 48 74 74 70 } //1 uploadOverHttp
		$a_01_2 = {75 70 64 61 74 65 4a 53 4f 4e 46 69 6c 65 50 61 74 68 } //1 updateJSONFilePath
		$a_01_3 = {66 72 69 65 6e 64 4b 65 79 3d } //1 friendKey=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}