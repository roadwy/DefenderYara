
rule Trojan_MacOS_Amos_DQ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DQ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 89 75 f0 48 8b 7d f8 48 89 7d e0 48 8b 45 f0 48 89 45 e8 e8 ab 2b 76 00 48 89 c1 48 8b 45 e8 48 39 c8 73 02 eb 05 } //1
		$a_01_1 = {31 c0 89 c6 48 8d 7d a8 ba 10 00 00 00 e8 b2 41 76 00 48 89 85 60 ff ff ff eb 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}