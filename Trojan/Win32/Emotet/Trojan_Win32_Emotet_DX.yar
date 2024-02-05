
rule Trojan_Win32_Emotet_DX{
	meta:
		description = "Trojan:Win32/Emotet.DX,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 2e 06 36 30 90 a0 79 a7 5e 2d 3c a6 1a 67 63 2a 17 58 ab 4b 69 3b 94 28 b4 3f 91 86 0f ac 89 71 67 1c c0 7d 91 8f 11 15 7a 97 09 bc 17 10 c7 77 b8 09 2e 06 36 30 90 a0 79 a7 5e 82 c5 8b 71 bd e6 16 27 e3 f0 5b f4 88 a0 b3 09 47 14 7e 0f 35 ce 65 f0 69 b0 06 e6 7b 85 38 ab 57 92 01 ff fb c7 02 fd f1 b9 53 26 ba a4 a1 04 1c 4a b5 50 ac 9d 27 64 b5 94 4c e4 43 f2 80 7c 9d 98 ca d6 72 92 70 99 cf c6 79 83 d2 1a 74 67 98 66 ab 94 01 27 9b 14 83 43 5e 36 89 2e 30 19 e5 71 30 ab 21 c5 fb 0a db 7e 15 39 e3 f0 37 f4 88 00 } //00 00 
	condition:
		any of ($a_*)
 
}