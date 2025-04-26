
rule Trojan_AndroidOS_FakeApp_D{
	meta:
		description = "Trojan:AndroidOS/FakeApp.D,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 73 65 43 2f 6e 43 2f 73 78 71 68 77 75 2f 58 65 42 74 70 75 69 69 71 77 75 } //1 LseC/nC/sxqhwu/XeBtpuiiqwu
		$a_01_1 = {41 6e 61 6c 79 73 65 44 61 74 61 20 42 42 58 52 55 72 6c } //1 AnalyseData BBXRUrl
		$a_01_2 = {48 61 6e 6c 64 65 52 75 6c 65 20 6e 75 6d 62 65 72 20 6e 75 6c 6c 20 64 61 74 61 20 6e 75 6c 6c } //1 HanldeRule number null data null
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}