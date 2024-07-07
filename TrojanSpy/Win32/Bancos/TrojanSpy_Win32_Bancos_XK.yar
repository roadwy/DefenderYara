
rule TrojanSpy_Win32_Bancos_XK{
	meta:
		description = "TrojanSpy:Win32/Bancos.XK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 43 6c 69 63 6b 13 00 90 02 08 49 6d 61 67 65 90 10 03 00 43 6c 69 63 6b 90 00 } //1
		$a_03_1 = {68 74 74 70 3a 2f 2f 90 02 20 2f 70 6c 75 67 69 6e 73 2f 75 73 65 72 2f 65 6e 76 69 61 2e 70 68 70 90 00 } //1
		$a_01_2 = {21 41 44 48 3a 52 43 34 2b 52 53 41 3a 2b 48 49 47 48 3a 2b 4d 45 44 49 55 4d 3a 2b 4c 4f 57 3a 2b 53 53 4c 76 32 3a 2b 45 58 50 } //1 !ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}