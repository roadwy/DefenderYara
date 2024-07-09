
rule VirTool_BAT_Injector_DO_bit{
	meta:
		description = "VirTool:BAT/Injector.DO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8c 16 00 00 01 a2 [0-04] 14 28 20 00 00 0a [0-04] b4 8c 14 00 00 01 28 23 00 00 0a 28 24 00 00 0a } //1
		$a_03_1 = {28 1f 00 00 0a [0-04] 1b d6 [0-04] 20 ff 00 00 00 5f d8 } //1
		$a_01_2 = {4c 61 74 65 49 6e 64 65 78 47 65 74 00 41 64 64 4f 62 6a 65 63 74 00 4d 6f 64 4f 62 6a 65 63 74 00 58 6f 72 4f 62 6a 65 63 74 00 54 6f 42 79 74 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}