
rule Trojan_AndroidOS_Triada_M{
	meta:
		description = "Trojan:AndroidOS/Triada.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6f 72 6c 2e 69 64 65 2e 53 73 } //2 com.orl.ide.Ss
		$a_01_1 = {61 70 6b 64 6f 77 6e 6c 6f 61 64 55 52 4c } //1 apkdownloadURL
		$a_01_2 = {64 65 6c 61 79 73 78 74 69 6d 65 73 61 5f 66 69 72 73 74 } //1 delaysxtimesa_first
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}