
rule Trojan_MacOS_Amos_CA_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 01 12 00 00 0f be f0 48 89 df e8 b7 12 00 00 48 89 df e8 b5 12 00 00 48 89 d8 48 83 c4 08 5b 5d c3 } //1
		$a_01_1 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 8b 06 48 89 07 48 8b 4e 40 48 8b 40 e8 48 89 0c 07 48 8b 46 48 48 89 47 10 48 83 c7 18 e8 7a 00 00 00 48 83 c3 08 4c 89 f7 48 89 de 5b 41 5e 5d e9 b0 11 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}