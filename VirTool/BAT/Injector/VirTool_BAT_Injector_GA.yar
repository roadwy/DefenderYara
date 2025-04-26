
rule VirTool_BAT_Injector_GA{
	meta:
		description = "VirTool:BAT/Injector.GA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {7e 0b 00 00 04 07 7e 0b 00 00 04 07 91 7e 04 00 00 04 07 7e 04 00 00 04 8e 69 5d 91 61 d2 9c 07 17 58 0b } //1
		$a_01_1 = {7e 0b 00 00 04 07 7e 0b 00 00 04 07 91 7e 04 00 00 04 08 91 06 1f 1f 5f 62 08 61 07 58 61 d2 9c 08 17 58 0c } //1
		$a_01_2 = {77 7a 78 73 63 75 59 54 2e 70 4c 65 67 76 6f 48 65 } //1 wzxscuYT.pLegvoHe
		$a_01_3 = {00 72 6f 73 74 61 6d 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}