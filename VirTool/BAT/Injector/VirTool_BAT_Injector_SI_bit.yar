
rule VirTool_BAT_Injector_SI_bit{
	meta:
		description = "VirTool:BAT/Injector.SI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 4d 65 74 68 6f 64 42 61 73 65 00 49 6e 76 6f 6b 65 } //1 敧彴湅牴偹楯瑮䴀瑥潨䉤獡e湉潶敫
		$a_01_1 = {06 1b 58 7e 18 00 00 04 8e 69 58 0b 7e 0e 00 00 04 06 91 0c 7e 18 00 00 04 06 1f 1c 5d 91 07 1f 1f 5f 63 0d 09 28 04 00 00 06 13 04 7e 0e 00 00 04 06 08 11 04 28 06 00 00 06 9c 06 17 58 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}