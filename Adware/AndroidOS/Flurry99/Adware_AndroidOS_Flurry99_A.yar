
rule Adware_AndroidOS_Flurry99_A{
	meta:
		description = "Adware:AndroidOS/Flurry99.A,SIGNATURE_TYPE_ELFHSTR_EXT,1f 00 1f 00 08 00 00 "
		
	strings :
		$a_01_0 = {4a 61 76 61 5f 63 6f 6d 5f 66 6c 75 72 72 79 5f 73 64 6b 5f 6e 61 5f 53 6f 67 74 } //16 Java_com_flurry_sdk_na_Sogt
		$a_01_1 = {77 64 6d 6e 67 70 72 } //3 wdmngpr
		$a_01_2 = {76 67 72 6c 61 79 70 72 } //3 vgrlaypr
		$a_01_3 = {61 76 6d 74 65 76 } //3 avmtev
		$a_01_4 = {61 6c 72 6d 70 61 74 68 } //3 alrmpath
		$a_01_5 = {41 45 53 5f 43 42 43 5f 64 65 63 72 79 70 74 } //1 AES_CBC_decrypt
		$a_01_6 = {41 45 53 5f 43 42 43 5f 65 6e 63 72 79 70 74 } //1 AES_CBC_encrypt
		$a_01_7 = {62 36 34 5f 64 65 63 6f 64 65 } //1 b64_decode
	condition:
		((#a_01_0  & 1)*16+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=31
 
}