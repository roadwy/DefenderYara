
rule Trojan_MacOS_Amos_AT_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AT!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c3 00 d1 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 08 aa 08 48 82 52 e8 1b 00 79 48 e2 88 52 28 e8 aa 72 e8 0b 00 b9 e8 23 00 91 00 01 40 b2 29 00 80 52 } //1
		$a_03_1 = {08 a4 40 a9 1f 01 09 eb 22 ?? ?? ?? 20 00 c0 3d 29 08 40 f9 09 09 00 f9 00 85 81 3c 3f fc 00 a9 3f 00 00 f9 08 04 00 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}