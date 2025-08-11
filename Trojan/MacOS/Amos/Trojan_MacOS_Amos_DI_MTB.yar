
rule Trojan_MacOS_Amos_DI_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DI!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 37 40 f6 c6 01 74 06 49 8b 7f 08 eb 04 89 f7 d1 ef 48 39 f9 73 19 48 89 c7 40 f6 c6 01 74 04 49 8b 7f 10 } //1
		$a_01_1 = {55 48 89 e5 48 89 f8 0f b6 0f f6 c1 01 75 07 48 ff c0 d1 e9 eb 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}