
rule Trojan_MacOS_Amos_DD_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DD!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ab 5e 40 39 6a 1d 00 13 ac 06 40 f9 5f 01 00 71 8b b1 8b 9a 1f 01 0b eb 02 01 00 54 ab 02 40 f9 5f 01 00 71 6a b1 95 9a 4a 69 68 38 28 79 2a b8 08 05 00 91 } //1
		$a_01_1 = {08 00 80 52 15 00 80 52 7f 7e 00 a9 7f 0a 00 f9 89 5e 40 39 2a 1d 00 13 8b 32 40 a9 5f 01 00 71 74 b1 94 9a 89 b1 89 9a 96 02 09 8b 9f 02 16 eb 20 02 00 54 89 02 40 39 ea 07 40 f9 49 79 69 b8 69 01 f8 37 35 19 15 2a 08 19 00 11 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}