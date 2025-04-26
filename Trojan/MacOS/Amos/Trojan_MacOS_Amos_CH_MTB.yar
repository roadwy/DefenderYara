
rule Trojan_MacOS_Amos_CH_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CH!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 03 15 aa ad 00 00 94 e0 03 14 aa ab 00 00 94 e0 03 13 aa a9 00 00 94 00 00 80 52 fd 7b 4e a9 f4 4f 4d a9 f6 57 4c a9 ff c3 03 91 c0 03 5f d6 } //1
		$a_01_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f4 03 00 aa 00 02 80 52 35 00 00 94 f3 03 00 aa e1 03 14 aa 0c 00 00 94 61 00 00 b0 21 0c 40 f9 62 00 00 b0 42 00 40 f9 e0 03 13 aa 3b 00 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}