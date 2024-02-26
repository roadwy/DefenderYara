
rule Backdoor_BAT_Remcos_ZM_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.ZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {0b 00 2b 35 16 2b 35 2b 3a 2b 3f 00 2b 0b 2b 0c 6f 90 01 03 0a 00 00 de 14 08 2b f2 07 2b f1 08 2c 0a 16 2d 06 08 6f 90 01 03 0a 00 dc 07 6f 90 01 03 0a 0d 16 2d cb de 30 06 2b c8 73 90 01 03 0a 2b c4 73 90 01 03 0a 2b bf 0c 2b be 90 00 } //01 00 
		$a_01_1 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //01 00  EnumProcessModules
		$a_01_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_4 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}