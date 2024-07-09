
rule VirTool_BAT_Injector_IH{
	meta:
		description = "VirTool:BAT/Injector.IH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {91 61 9c 11 ?? 17 58 13 ?? 11 ?? 11 ?? 31 } //1
		$a_01_1 = {67 65 74 5f 42 69 73 71 75 65 00 67 65 74 5f 4d 61 67 65 6e 74 61 00 67 65 74 5f 4c 69 6d 65 00 } //1 敧彴楂煳敵最瑥䵟条湥慴最瑥䱟浩e
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}