
rule Trojan_MacOS_Amos_CM_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CM!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f5 03 01 aa f3 03 00 aa e0 03 01 aa 55 00 00 94 e8 eb 7c b2 1f 00 08 eb 62 ?? ?? ?? f4 03 00 aa 1f 5c 00 f1 a2 ?? ?? ?? 74 5e 00 39 f6 03 13 aa } //1
		$a_01_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f4 03 00 aa 00 02 80 52 73 00 00 94 f3 03 00 aa e1 03 14 aa 0c 00 00 94 61 00 00 b0 21 08 40 f9 62 00 00 b0 42 00 40 f9 e0 03 13 aa 70 00 00 94 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}