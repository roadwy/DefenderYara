
rule Trojan_MacOS_Amos_DJ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DJ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e0 48 8b 45 f0 48 89 45 e8 e8 ab 7f 52 00 48 89 c1 48 8b 45 e8 48 39 c8 0f 83 05 00 00 00 e9 05 00 00 00 } //1
		$a_01_1 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 7d f8 e8 8b 95 52 00 48 83 c4 10 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}