
rule VirTool_BAT_Injector_JA_bit{
	meta:
		description = "VirTool:BAT/Injector.JA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 24 00 00 0a 72 90 01 01 00 00 70 6f 25 00 00 0a 0a 06 6f 26 00 00 0a d4 8d 1a 00 00 01 0b 06 07 16 07 8e 69 6f 27 00 00 0a 26 07 0c de 0a 90 00 } //1
		$a_01_1 = {06 d3 08 58 06 d3 08 58 47 07 d3 08 02 7b 04 00 00 04 8e 69 5d 58 47 61 d2 52 08 17 58 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}