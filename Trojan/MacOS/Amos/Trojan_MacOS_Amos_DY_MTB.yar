
rule Trojan_MacOS_Amos_DY_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DY!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c3 02 d1 fd 7b 0a a9 fd 83 02 91 e8 17 00 f9 a8 83 1f f8 a0 03 1f f8 a8 63 00 d1 e8 1b 00 f9 a1 83 1e f8 a2 03 1e f8 a3 83 1d f8 a4 03 1d f8 a0 03 5f f8 a8 fc ff 97 a0 83 1c f8 08 00 80 52 e8 17 00 b9 08 01 00 12 08 01 00 12 a8 73 1c 38 a0 83 5c f8 21 00 80 d2 57 01 00 94 e8 17 40 b9 e0 0f 00 f9 a1 83 5c f8 e0 43 01 91 e0 13 00 f9 02 01 00 12 } //1
		$a_01_1 = {e8 5b 40 f9 00 41 00 91 99 fd ff 97 8c 01 00 94 a0 03 15 f8 a8 03 55 f8 08 01 40 f9 e8 23 00 f9 a0 23 02 d1 e0 27 00 f9 8e 01 00 94 e8 23 40 f9 e9 03 00 aa e0 27 40 f9 28 01 00 f9 93 01 00 94 7f 01 00 94 e8 03 00 aa e0 5b 40 f9 a9 03 55 f8 28 01 00 f9 a8 03 55 f8 e8 2b 00 f9 a1 03 59 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}