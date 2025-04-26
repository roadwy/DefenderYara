
rule VirTool_BAT_Injector_VE_bit{
	meta:
		description = "VirTool:BAT/Injector.VE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0b 02 07 8f ?? 00 00 01 25 47 03 06 ?? 6f 04 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ?? 00 00 00 5f d2 61 d2 52 06 17 58 0a 06 02 8e 69 } //1
		$a_01_1 = {67 65 74 5f 4c 65 6e 67 74 68 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 49 6e 76 6f 6b 65 } //1 敧彴敌杮桴最瑥䕟瑮祲潐湩t湉潶敫
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}