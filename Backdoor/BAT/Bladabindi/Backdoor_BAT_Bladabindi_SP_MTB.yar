
rule Backdoor_BAT_Bladabindi_SP_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 7e 05 00 00 04 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 06 14 14 7e 09 00 00 04 74 01 00 00 1b 6f ?? ?? ?? 0a 26 17 28 ?? ?? ?? 0a 7e 03 00 00 04 2d ba } //4
		$a_01_1 = {67 65 74 64 65 63 72 79 70 74 69 74 } //1 getdecryptit
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
rule Backdoor_BAT_Bladabindi_SP_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {34 65 61 36 63 63 36 64 2d 30 36 33 65 2d 34 33 63 66 2d 39 36 63 65 2d 62 33 65 63 31 62 37 30 37 62 63 35 } //2 4ea6cc6d-063e-43cf-96ce-b3ec1b707bc5
		$a_01_1 = {61 73 64 6a 4a 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 asdjJ.My.Resources
		$a_01_2 = {45 62 56 6b 39 64 4d 57 76 6f 64 73 75 30 46 67 5a 52 2e 4e 6d 55 52 74 73 5a 48 34 4e 50 4e 47 5a 50 53 42 67 } //2 EbVk9dMWvodsu0FgZR.NmURtsZH4NPNGZPSBg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}