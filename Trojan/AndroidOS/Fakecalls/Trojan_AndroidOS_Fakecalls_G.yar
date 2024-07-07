
rule Trojan_AndroidOS_Fakecalls_G{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 53 52 43 5f 4e 55 4d 42 45 52 } //1 KEY_SRC_NUMBER
		$a_01_1 = {43 61 6c 6c 4f 75 74 5f 4e 75 6d 62 65 72 3d } //1 CallOut_Number=
		$a_01_2 = {4b 45 59 5f 53 45 52 56 45 52 5f 49 50 31 } //1 KEY_SERVER_IP1
		$a_01_3 = {64 65 6c 61 79 20 32 73 65 63 20 63 61 6c 6c 20 65 6e 64 } //1 delay 2sec call end
		$a_01_4 = {4b 45 59 5f 54 45 4c 45 43 4f 4d 53 5f 4e 41 4d 45 31 } //1 KEY_TELECOMS_NAME1
		$a_01_5 = {63 68 61 6e 67 65 20 6f 76 65 72 6c 61 79 20 6e 75 6d 62 65 72 3a } //1 change overlay number:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}