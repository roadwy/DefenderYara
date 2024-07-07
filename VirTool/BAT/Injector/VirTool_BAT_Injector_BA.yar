
rule VirTool_BAT_Injector_BA{
	meta:
		description = "VirTool:BAT/Injector.BA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 20 82 fb 9d 4e 61 0b 90 02 05 08 20 57 e1 0d 4a 61 0c 2b 90 01 01 09 20 26 c1 bd 5b 61 0d 2b 90 00 } //1
		$a_03_1 = {20 eb 2b 9c 5b 0d 2b 90 02 09 ff ff 20 ef 6a 53 15 13 05 90 00 } //1
		$a_01_2 = {39 6f 00 66 00 66 00 73 00 65 00 74 00 20 00 2b 00 20 00 63 00 6f 00 75 00 6e 00 74 00 20 00 6f 00 75 00 74 00 20 00 6f 00 66 00 20 00 62 00 75 00 66 00 66 00 65 00 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}