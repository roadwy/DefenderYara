
rule Trojan_BAT_AsyncRAT_RDAB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 37 63 35 66 32 32 66 2d 39 66 39 38 2d 34 39 30 31 2d 39 62 33 33 2d 63 64 66 33 30 38 64 65 36 33 33 39 } //2 27c5f22f-9f98-4901-9b33-cdf308de6339
		$a_01_1 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 } //1 ConsoleApplication1
		$a_01_2 = {77 61 66 61 61 73 65 78 } //1 wafaasex
		$a_01_3 = {76 63 78 72 74 65 72 72 65 72 } //1 vcxrterrer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}