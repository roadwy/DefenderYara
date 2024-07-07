
rule Trojan_AndroidOS_SAgnt_BA_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 48 43 61 6d 65 72 61 53 75 72 66 61 63 65 } //1 SHCameraSurface
		$a_01_1 = {4b 65 6f 6e 61 44 65 6d 6f 41 63 74 } //1 KeonaDemoAct
		$a_01_2 = {61 72 69 61 63 72 79 70 74 5f 65 6e 61 62 6c 65 } //1 ariacrypt_enable
		$a_01_3 = {2f 61 70 6b 2f 70 64 61 69 64 2e 74 78 74 } //1 /apk/pdaid.txt
		$a_01_4 = {6e 6f 6e 70 61 79 2e 63 6f 2e 6b 72 } //1 nonpay.co.kr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}