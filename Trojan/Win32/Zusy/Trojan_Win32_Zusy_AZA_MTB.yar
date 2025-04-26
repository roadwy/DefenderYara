
rule Trojan_Win32_Zusy_AZA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 d4 f7 c6 45 d5 59 c6 45 d6 57 c6 45 d7 af c6 45 d8 3a c6 45 d9 5e c6 45 da ee c6 45 db c0 c6 45 dc 43 c6 45 dd ee c6 45 de 9a c6 45 df 39 c6 45 e0 9d c6 45 e1 71 c6 45 e2 92 c6 45 e3 8a c6 45 e4 4f c6 45 e5 b3 c6 45 e6 a3 c6 45 e7 3b c6 45 e8 52 } //2
		$a_01_1 = {c6 45 d9 fe c6 45 da c4 c6 45 db 9e c6 45 dc d8 c6 45 dd 87 c6 45 de 49 c6 45 df 65 c6 45 e0 5a c6 45 e1 98 c6 45 e2 82 c6 45 e3 2c c6 45 e4 28 c6 45 e5 ce c6 45 e6 89 c6 45 e7 6f c6 45 e8 b3 c6 45 e9 65 c6 45 ea e9 c6 45 eb 70 c6 45 ec 1b c6 45 ed 0b c6 45 ee 9c c6 45 ef d6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}