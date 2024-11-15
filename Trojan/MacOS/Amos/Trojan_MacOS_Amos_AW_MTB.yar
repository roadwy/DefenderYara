
rule Trojan_MacOS_Amos_AW_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AW!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 07 40 f9 e9 03 00 aa e0 03 40 f9 e9 0f 00 f9 e9 03 01 aa e9 17 00 b9 01 21 00 91 e8 0f 00 94 } //1
		$a_01_1 = {ff c3 00 d1 fd 7b 02 a9 fd 83 00 91 88 00 00 d0 08 c1 0a 91 09 41 00 91 a0 83 1f f8 a8 83 5f f8 e8 03 00 f9 09 01 00 f9 00 01 01 91 a0 0f 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}