
rule Trojan_MacOS_Amos_DE_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DE!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 43 01 d1 f6 57 02 a9 f4 4f 03 a9 fd 7b 04 a9 fd 03 01 91 f3 03 08 aa 08 5c 40 39 09 1d 00 13 0a 04 40 f9 3f 01 00 71 48 b1 88 9a c8 ?? ?? ?? f4 03 00 aa 7f 7e 00 a9 01 fd 41 d3 7f 0a 00 f9 e0 03 13 aa } //1
		$a_01_1 = {08 00 80 52 15 00 80 52 7f 7e 00 a9 7f 0a 00 f9 89 5e 40 39 2a 1d 00 13 8b 32 40 a9 5f 01 00 71 74 b1 94 9a 89 b1 89 9a 96 02 09 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}