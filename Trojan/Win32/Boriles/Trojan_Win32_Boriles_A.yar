
rule Trojan_Win32_Boriles_A{
	meta:
		description = "Trojan:Win32/Boriles.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 30 00 4a 00 51 00 54 00 46 00 56 00 48 00 53 00 55 00 34 00 3d 00 } //1 R0JQTFVHSU4=
		$a_01_1 = {58 00 46 00 64 00 70 00 62 00 6d 00 52 00 76 00 64 00 33 00 4d 00 67 00 52 00 47 00 56 00 6d 00 5a 00 57 00 35 00 6b 00 5a 00 58 00 49 00 3d 00 } //1 XFdpbmRvd3MgRGVmZW5kZXI=
		$a_01_2 = {53 00 57 00 35 00 6d 00 62 00 33 00 4a 00 74 00 59 00 54 00 38 00 2f 00 5a 00 58 00 4d 00 67 00 5a 00 47 00 55 00 67 00 55 00 32 00 56 00 6e 00 64 00 58 00 4a 00 68 00 62 00 6a 00 39 00 68 00 } //1 SW5mb3JtYT8/ZXMgZGUgU2VndXJhbj9h
		$a_01_3 = {55 00 33 00 56 00 75 00 51 00 58 00 64 00 30 00 52 00 47 00 6c 00 68 00 62 00 47 00 39 00 6e 00 } //1 U3VuQXd0RGlhbG9n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}