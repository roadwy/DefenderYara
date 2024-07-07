
rule VirTool_BAT_Injector_VJ_bit{
	meta:
		description = "VirTool:BAT/Injector.VJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 90 01 02 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 90 01 02 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 90 00 } //1
		$a_03_1 = {03 04 61 1f 90 01 01 59 06 61 45 01 00 00 00 10 00 00 00 09 20 90 01 04 94 20 90 01 04 59 0c 2b ab 1e 2b fa 90 00 } //1
		$a_01_2 = {00 46 6f 72 4d 65 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}