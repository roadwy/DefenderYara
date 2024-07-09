
rule Trojan_Linux_Mirai_CC{
	meta:
		description = "Trojan:Linux/Mirai.CC,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_02_0 = {24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 20 2d 6c 20 2f 74 6d 70 2f [0-09] 20 2d 72 20 2f 78 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f 73 6b 65 72 65 3b 20 2f 74 6d 70 2f 73 6b 65 72 65 20 68 75 61 77 65 69 29 } //4
		$a_01_1 = {53 45 52 56 5a 55 58 4f } //3 SERVZUXO
		$a_00_2 = {2f 76 61 72 2f 53 6f 66 69 61 } //3 /var/Sofia
		$a_00_3 = {2f 73 79 73 74 65 6d 2f 73 79 73 74 65 6d 2f 62 69 6e 2f } //2 /system/system/bin/
	condition:
		((#a_02_0  & 1)*4+(#a_01_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*2) >=9
 
}