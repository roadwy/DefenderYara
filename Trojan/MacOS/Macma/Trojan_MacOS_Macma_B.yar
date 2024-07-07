
rule Trojan_MacOS_Macma_B{
	meta:
		description = "Trojan:MacOS/Macma.B,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 63 63 63 2e 6b 65 79 62 6f 61 72 64 72 65 63 6f 72 64 } //2 com.ccc.keyboardrecord
		$a_01_1 = {75 73 65 61 67 65 20 25 73 20 70 61 74 68 20 75 73 65 72 61 67 65 6e 74 70 69 64 } //1 useage %s path useragentpid
		$a_01_2 = {63 6f 6d 2e 63 63 63 2e 77 72 69 74 65 5f 71 75 65 75 65 00 66 69 6c 65 20 69 73 20 00 25 59 2d 25 6d 2d 25 64 20 25 48 3a 25 4d 3a 25 53 00 77 00 70 73 20 2d 70 20 25 73 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //1
		$a_02_3 = {41 5e 5d c3 4c 8d 90 01 03 ff ff bf 01 00 00 00 31 f6 31 d2 b9 00 0c 00 00 49 89 d9 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=5
 
}