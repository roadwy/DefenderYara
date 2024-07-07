
rule Trojan_BAT_SnakeKeylogger_DY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {4d 69 6c 6c 69 6f 6e 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Millionare.Properties.Resources
		$a_81_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_2 = {44 6f 6e 74 4c 65 74 55 73 65 72 4c 6f 67 69 6e } //1 DontLetUserLogin
		$a_81_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}