
rule TrojanSpy_BAT_JsLoader_SA_MSR{
	meta:
		description = "TrojanSpy:BAT/JsLoader.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 28 } //1 SELE(
		$a_01_1 = {43 54 20 53 28 } //1 CT S(
		$a_01_2 = {46 52 4f 4d 28 } //1 FROM(
		$a_01_3 = {4a 73 73 48 74 74 70 } //3 JssHttp
		$a_00_4 = {48 00 6f 00 73 00 74 00 20 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 72 00 65 00 70 00 6f 00 72 00 74 00 } //3 Host information report
		$a_01_5 = {48 00 65 00 72 00 65 00 20 00 63 00 6f 00 75 00 6c 00 64 00 20 00 62 00 65 00 } //3 Here could be
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_00_4  & 1)*3+(#a_01_5  & 1)*3) >=10
 
}