
rule TrojanSpy_Win32_Bancos_SN{
	meta:
		description = "TrojanSpy:Win32/Bancos.SN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 a7 53 cf a7 7a 07 98 fd 00 41 ea 7a d3 16 36 88 fc 80 30 f7 e0 fe 75 32 4a a4 e0 e5 5b d0 d5 7a 13 7e e2 a4 2a 0e 4e 59 bd 4d 4c 05 57 f3 94 5d 18 9c ba ae d5 60 50 0c e4 ee eb 9f a5 4d be } //01 00 
		$a_01_1 = {a9 ae 85 f4 16 d6 cf 0c 7b e3 92 46 69 23 2f f7 4a 0c 00 18 7f 7a 9d e5 6a 7f f3 f7 69 ff 00 80 ad ff 00 c7 29 25 ff 00 90 dd af fd 7b 4d ff 00 a1 45 57 a8 02 97 95 a9 ff 00 cf dd a7 fe 02 b7 } //00 00 
	condition:
		any of ($a_*)
 
}