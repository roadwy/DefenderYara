
rule VirTool_BAT_MaliciousMSILLoaderKazy_A{
	meta:
		description = "VirTool:BAT/MaliciousMSILLoaderKazy.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 9c 11 90 01 01 17 58 13 90 00 } //10
		$a_01_1 = {69 59 11 05 58 11 04 11 05 91 9c 11 05 17 58 13 05 11 05 11 04 8e 69 32 d8 09 17 58 0d 09 20 } //10
		$a_01_2 = {64 00 6f 00 68 00 74 00 65 00 4d 00 74 00 65 00 47 00 } //1 dohteMteG
		$a_01_3 = {52 65 73 69 7a 65 } //1 Resize
		$a_01_4 = {72 00 65 00 64 00 61 00 6f 00 4c 00 79 00 7a 00 61 00 4b 00 } //1 redaoLyzaK
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}