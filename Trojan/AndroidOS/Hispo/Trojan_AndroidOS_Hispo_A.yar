
rule Trojan_AndroidOS_Hispo_A{
	meta:
		description = "Trojan:AndroidOS/Hispo.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 6e 66 6f 2e 6b 75 36 2e 63 6e 2f 63 6c 69 65 6e 74 52 65 71 75 65 73 74 2e 68 74 6d } //1 http://info.ku6.cn/clientRequest.htm
		$a_01_1 = {3f 6d 65 74 68 6f 64 3d 68 6f 74 4b 65 79 77 6f 72 64 26 63 74 3d 61 6e 64 72 6f 69 64 } //1 ?method=hotKeyword&ct=android
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}