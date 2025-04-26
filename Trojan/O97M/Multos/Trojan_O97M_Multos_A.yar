
rule Trojan_O97M_Multos_A{
	meta:
		description = "Trojan:O97M/Multos.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 51 70 6c 65 47 56 6a 4b 43 63 6e 4c 6d 70 76 61 57 34 6f 62 33 56 30 4b 53 6b 3d } //1 KQpleGVjKCcnLmpvaW4ob3V0KSk=
		$a_01_1 = {73 79 73 74 65 6d 20 4c 69 62 20 22 6c 69 62 63 2e 64 79 6c 69 62 22 } //1 system Lib "libc.dylib"
		$a_01_2 = {22 69 6d 70 6f 72 74 20 73 79 73 2c 62 61 73 65 36 34 3b 65 78 65 63 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 } //1 "import sys,base64;exec(base64.b64decode
		$a_01_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}