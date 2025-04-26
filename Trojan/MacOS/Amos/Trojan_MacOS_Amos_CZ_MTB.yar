
rule Trojan_MacOS_Amos_CZ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CZ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 a5 02 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 f7 01 00 00 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 7d f0 e8 2b 01 00 00 48 8b 4d f0 48 8b 31 48 83 21 00 48 89 c7 e8 2e 00 00 00 48 8b 45 f0 ff 50 08 48 8d 7d f0 e8 2c 00 00 00 31 c0 48 83 c4 08 5b 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}