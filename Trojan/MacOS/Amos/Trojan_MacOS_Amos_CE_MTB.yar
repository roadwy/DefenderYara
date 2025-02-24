
rule Trojan_MacOS_Amos_CE_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CE!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 cb 05 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 91 02 00 00 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 fb 48 8b 07 48 8b 78 e8 48 01 df 6a 0a 5e e8 8f 04 00 00 0f be f0 48 89 df e8 39 05 00 00 48 89 df e8 37 05 00 00 48 89 d8 48 83 c4 08 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}