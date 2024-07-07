
rule Trojan_WinNT_Regin_C_dha{
	meta:
		description = "Trojan:WinNT/Regin.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 11 77 11 77 be 11 66 11 66 ff e0 } //1
		$a_01_1 = {8b 45 fc 8b 40 28 03 45 08 53 ff 75 08 ff d0 8b d8 f7 db 1a db } //1
		$a_01_2 = {c6 45 d8 4d c6 45 d9 6d c6 45 da 48 c6 45 db 69 c6 45 dc 67 c6 45 dd 68 c6 45 de 65 c6 45 df 73 c6 45 e0 74 c6 45 e1 55 c6 45 e2 73 c6 45 e3 65 c6 45 e4 72 c6 45 e5 41 c6 45 e6 64 c6 45 e7 64 c6 45 e8 72 c6 45 e9 65 c6 45 ea 73 c6 45 eb 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}