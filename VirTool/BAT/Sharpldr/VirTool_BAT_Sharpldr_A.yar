
rule VirTool_BAT_Sharpldr_A{
	meta:
		description = "VirTool:BAT/Sharpldr.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 65 6d 65 6e 74 6f 72 2e 65 78 65 00 6d 73 63 6f 72 6c 69 62 00 53 75 70 70 72 65 73 73 } //1 敄敭瑮牯攮數洀捳牯楬b畓灰敲獳
		$a_01_1 = {8f e2 81 ae e2 80 8e e2 80 aa e2 80 ab e2 80 8c e2 80 8e e2 80 ac e2 80 8e e2 } //1
		$a_01_2 = {81 ab e2 80 ad e2 81 ae e2 80 ad e2 81 aa e2 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}