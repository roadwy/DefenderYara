
rule Trojan_Win32_VBKrypt_AP_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 aa 31 86 11 04 f8 14 18 a4 16 2f 31 9d e4 e6 4b 2a db 81 a4 55 51 41 78 f8 1e e7 19 f9 12 00 6d fa aa 3f bc 31 90 c2 43 4f 73 } //1
		$a_01_1 = {46 33 f8 25 f7 05 44 f5 99 fe 21 a1 fb ad 6f 3f c3 53 32 60 a5 99 9e 4d fd 1e 23 36 0a 58 44 13 43 6f 7e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_VBKrypt_AP_MTB_2{
	meta:
		description = "Trojan:Win32/VBKrypt.AP!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 63 00 69 00 73 00 69 00 6f 00 6e 00 73 00 6d 00 6f 00 64 00 65 00 6c 00 6c 00 65 00 6e 00 } //1 Decisionsmodellen
		$a_01_1 = {53 00 54 00 4f 00 52 00 42 00 52 00 49 00 54 00 41 00 4e 00 4e 00 49 00 45 00 4e 00 53 00 } //1 STORBRITANNIENS
		$a_01_2 = {42 00 55 00 53 00 54 00 45 00 52 00 4d 00 49 00 4e 00 41 00 4c 00 45 00 52 00 4e 00 45 00 53 00 } //1 BUSTERMINALERNES
		$a_01_3 = {50 41 52 4b 45 52 49 4e 47 53 4c 59 47 54 45 52 } //1 PARKERINGSLYGTER
		$a_01_4 = {53 4d 41 41 42 4f 52 47 45 52 4c 49 47 53 54 45 } //1 SMAABORGERLIGSTE
		$a_01_5 = {4e 4f 4e 41 50 50 45 41 4c 49 4e 47 4c 59 } //1 NONAPPEALINGLY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}