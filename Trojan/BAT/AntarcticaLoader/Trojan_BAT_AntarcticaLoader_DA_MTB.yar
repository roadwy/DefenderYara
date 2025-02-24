
rule Trojan_BAT_AntarcticaLoader_DA_MTB{
	meta:
		description = "Trojan:BAT/AntarcticaLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0c 00 00 "
		
	strings :
		$a_80_0 = {4c 6f 61 64 65 72 56 32 2e 41 6e 74 69 44 65 62 75 67 67 69 6e 67 } //LoaderV2.AntiDebugging  10
		$a_80_1 = {41 6e 74 69 44 75 6d 70 } //AntiDump  10
		$a_80_2 = {47 65 74 50 68 79 73 69 63 61 6c 41 64 64 72 65 73 73 } //GetPhysicalAddress  1
		$a_80_3 = {75 73 65 72 5f 64 61 74 61 } //user_data  1
		$a_80_4 = {67 65 74 5f 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 } //get_SystemDirectory  1
		$a_80_5 = {67 65 74 5f 4f 53 56 65 72 73 69 6f 6e } //get_OSVersion  1
		$a_80_6 = {67 65 74 5f 50 6c 61 74 66 6f 72 6d } //get_Platform  1
		$a_80_7 = {47 65 74 48 6f 73 74 4e 61 6d 65 } //GetHostName  1
		$a_80_8 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //Base64String  1
		$a_80_9 = {52 65 76 65 72 73 65 } //Reverse  1
		$a_80_10 = {65 78 70 69 72 65 73 } //expires  1
		$a_80_11 = {75 73 65 72 6e 61 6d 65 } //username  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=30
 
}